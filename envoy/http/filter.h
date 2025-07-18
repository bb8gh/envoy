#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "envoy/access_log/access_log.h"
#include "envoy/buffer/buffer.h"
#include "envoy/common/scope_tracker.h"
#include "envoy/event/dispatcher.h"
#include "envoy/grpc/status.h"
#include "envoy/http/codec.h"
#include "envoy/http/filter_factory.h"
#include "envoy/http/header_map.h"
#include "envoy/matcher/matcher.h"
#include "envoy/router/router.h"
#include "envoy/router/scopes.h"
#include "envoy/ssl/connection.h"
#include "envoy/tracing/tracer.h"
#include "envoy/upstream/load_balancer.h"
#include "envoy/upstream/upstream.h"

#include "source/common/common/scope_tracked_object_stack.h"

#include "absl/types/optional.h"

namespace Envoy {
namespace Router {
class RouteConfigProvider;
}
namespace Http {

/**
 * Return codes for encode/decode headers filter invocations. The connection manager bases further
 * filter invocations on the return code of the previous filter.
 */
enum class FilterHeadersStatus {
  // Continue filter chain iteration.
  Continue,
  // Do not iterate for headers on any of the remaining filters in the chain.
  //
  // Returning FilterDataStatus::Continue from decodeData()/encodeData() or calling
  // continueDecoding()/continueEncoding() MUST be called if continued filter iteration is desired.
  //
  // Note that if a local reply was sent, no further iteration for headers as well as data and
  // trailers for the current filter and the filters following will happen. A local reply can be
  // triggered via sendLocalReply() or encodeHeaders().
  StopIteration,
  // Continue headers iteration to remaining filters, but delay ending the stream. This status MUST
  // NOT be returned when end_stream is already set to false.
  //
  // Used when a filter wants to add a body to a headers-only request/response, but this body is not
  // readily available. Delaying end_stream allows the filter to add the body once it's available
  // without stopping headers iteration.
  //
  // The filter is responsible to continue the stream by providing a body through calling
  // injectDecodedDataToFilterChain()/injectEncodedDataToFilterChain(), possibly multiple times
  // if the body needs to be divided into several chunks. The filter may need to handle
  // watermark events when injecting a body, see:
  // https://github.com/envoyproxy/envoy/blob/main/source/docs/flow_control.md.
  //
  // The last call to inject data MUST have end_stream set to true to conclude the stream.
  // If the filter cannot provide a body the stream should be reset.
  //
  // Adding a body through calling addDecodedData()/addEncodedData() then
  // continueDecoding()/continueEncoding() is currently NOT supported and causes an assert failure.
  //
  // Adding trailers in this scenario is currently NOT supported.
  //
  // The filter MUST NOT attempt to continue the stream without providing a body using
  // continueDecoding()/continueEncoding().
  //
  // TODO(yosrym93): Support adding a body in this case by calling addDecodedData()/addEncodedData()
  // then continueDecoding()/continueEncoding(). To support this a new FilterManager::IterationState
  // needs to be added and set when a filter returns this status in
  // FilterManager::decodeHeaders/FilterManager::encodeHeaders()
  // Currently, when a filter returns this, the IterationState is Continue. This causes ASSERTs in
  // FilterManager::commonContinue() to fail when continueDecoding()/continueEncoding() is called;
  // due to trying to continue iteration when the IterationState is already Continue.
  // In this case, a different ASSERT will be needed to make sure the filter does not try to
  // continue without adding a body first.
  //
  // TODO(yosrym93): Support adding trailers in this case by implementing new functions to inject
  // trailers, similar to the inject data functions.
  ContinueAndDontEndStream,
  // Do not iterate for headers as well as data and trailers for the current filter and the filters
  // following, and buffer body data for later dispatching. ContinueDecoding() MUST
  // be called if continued filter iteration is desired.
  //
  // Used when a filter wants to stop iteration on data and trailers while waiting for headers'
  // iteration to resume.
  //
  // If buffering the request causes buffered data to exceed the configured buffer limit, a 413 will
  // be sent to the user. On the response path exceeding buffer limits will result in a 500.
  //
  // TODO(soya3129): stop metadata parsing when StopAllIterationAndBuffer is set.
  StopAllIterationAndBuffer,
  // Do not iterate for headers as well as data and trailers for the current filter and the filters
  // following, and buffer body data for later dispatching. continueDecoding() MUST
  // be called if continued filter iteration is desired.
  //
  // Used when a filter wants to stop iteration on data and trailers while waiting for headers'
  // iteration to resume.
  //
  // This will cause the flow of incoming data to cease until continueDecoding() function is called.
  //
  // TODO(soya3129): stop metadata parsing when StopAllIterationAndWatermark is set.
  StopAllIterationAndWatermark,
};

/**
 * Return codes for encode on informative headers filter invocations.
 */
enum class Filter1xxHeadersStatus {
  // Continue filter chain iteration.
  Continue,
  // Do not iterate for informative headers on any of the remaining filters in the chain.
  //
  // Returning FilterDataStatus::Continue from encodeData() or calling
  // continueEncoding() MUST be called if continued filter iteration is desired.
  StopIteration
};

/**
 * Return codes for encode/decode data filter invocations. The connection manager bases further
 * filter invocations on the return code of the previous filter.
 */
enum class FilterDataStatus {
  // Continue filter chain iteration. If headers have not yet been sent to the next filter, they
  // will be sent first via decodeHeaders()/encodeHeaders(). If data has previously been buffered,
  // the data in this callback will be added to the buffer before the entirety is sent to the next
  // filter.
  Continue,
  // Do not iterate to any of the remaining filters in the chain, and buffer body data for later
  // dispatching. Returning FilterDataStatus::Continue from decodeData()/encodeData() or calling
  // continueDecoding()/continueEncoding() MUST be called if continued filter iteration is desired.
  //
  // This should be called by filters which must parse a larger block of the incoming data before
  // continuing processing and so can not push back on streaming data via watermarks.
  //
  // If buffering the request causes buffered data to exceed the configured buffer limit, a 413 will
  // be sent to the user. On the response path exceeding buffer limits will result in a 500.
  StopIterationAndBuffer,
  // Do not iterate to any of the remaining filters in the chain, and buffer body data for later
  // dispatching. Returning FilterDataStatus::Continue from decodeData()/encodeData() or calling
  // continueDecoding()/continueEncoding() MUST be called if continued filter iteration is desired.
  //
  // This will cause the flow of incoming data to cease until one of the continue.*() functions is
  // called.
  //
  // This should be returned by filters which can nominally stream data but have a transient back-up
  // such as the configured delay of the fault filter, or if the router filter is still fetching an
  // upstream connection.
  StopIterationAndWatermark,
  // Do not iterate to any of the remaining filters in the chain, but do not buffer any of the
  // body data for later dispatching. Returning FilterDataStatus::Continue from
  // decodeData()/encodeData() or calling continueDecoding()/continueEncoding() MUST be called if
  // continued filter iteration is desired.
  //
  // Note that if a local reply was sent, no further iteration for either data or trailers
  // for the current filter and the filters following will happen. A local reply can be
  // triggered via sendLocalReply() or encodeHeaders().
  StopIterationNoBuffer
};

/**
 * Return codes for encode/decode trailers filter invocations. The connection manager bases further
 * filter invocations on the return code of the previous filter.
 */
enum class FilterTrailersStatus {
  // Continue filter chain iteration.
  Continue,
  // Do not iterate to any of the remaining filters in the chain. Calling
  // continueDecoding()/continueEncoding() MUST be called if continued filter iteration is desired.
  StopIteration
};

/**
 * Return codes for encode metadata filter invocations. Metadata currently can not stop filter
 * iteration except in the case of local replies.
 */
enum class FilterMetadataStatus {
  // Continue filter chain iteration for metadata only. Does not unblock returns of StopIteration*
  // from (decode|encode)(Headers|Data).
  Continue,

  // Continue filter chain iteration. If headers have not yet been sent to the next filter, they
  // will be sent first via (decode|encode)Headers().
  ContinueAll,

  // Stops iteration of the entire filter chain. Only to be used in the case of sending a local
  // reply from (decode|encode)Metadata.
  StopIterationForLocalReply,
};

/**
 * Return codes for onLocalReply filter invocations.
 */
enum class LocalErrorStatus {
  // Continue sending the local reply after onLocalReply has been sent to all filters.
  Continue,

  // Continue sending onLocalReply to all filters, but reset the stream once all filters have been
  // informed rather than sending the local reply.
  ContinueAndResetStream,
};

// These are events that upstream HTTP filters can register for, via the addUpstreamCallbacks
// function.
class UpstreamCallbacks {
public:
  virtual ~UpstreamCallbacks() = default;

  // Called when the upstream connection is established and
  // UpstreamStreamFilterCallbacks::upstream should be available.
  //
  // This indicates that data may begin flowing upstream.
  virtual void onUpstreamConnectionEstablished() PURE;
};

// These are filter callbacks specific to upstream HTTP filters, accessible via
// StreamFilterCallbacks::upstreamCallbacks()
class UpstreamStreamFilterCallbacks {
public:
  virtual ~UpstreamStreamFilterCallbacks() = default;

  // Returns a handle to the upstream stream's stream info.
  virtual StreamInfo::StreamInfo& upstreamStreamInfo() PURE;

  // Returns a handle to the generic upstream.
  virtual OptRef<Router::GenericUpstream> upstream() PURE;

  // Dumps state for the upstream request.
  virtual void dumpState(std::ostream& os, int indent_level = 0) const PURE;

  // Setters and getters to determine if sending body payload is paused on
  // confirmation of a CONNECT upgrade. These should only be used by the upstream codec filter.
  // TODO(alyssawilk) after deprecating the classic path, move this logic to the
  // upstream codec filter and remove these APIs
  virtual bool pausedForConnect() const PURE;
  virtual void setPausedForConnect(bool value) PURE;

  // Setters and getters to determine if sending body payload is paused on
  // confirmation of a WebSocket upgrade. These should only be used by the upstream codec filter.
  virtual bool pausedForWebsocketUpgrade() const PURE;
  virtual void setPausedForWebsocketUpgrade(bool value) PURE;

  // Return the upstreamStreamOptions for this stream.
  virtual const Http::ConnectionPool::Instance::StreamOptions& upstreamStreamOptions() const PURE;

  // Adds the supplied UpstreamCallbacks to the list of callbacks to be called
  // as various upstream events occur. Callbacks should persist for the lifetime
  // of the upstream stream.
  virtual void addUpstreamCallbacks(UpstreamCallbacks& callbacks) PURE;

  // This should only be called by the UpstreamCodecFilter, and is used to let the
  // UpstreamCodecFilter supply the interface used by the GenericUpstream to receive
  // response data from the upstream stream once it is established.
  virtual void
  setUpstreamToDownstream(Router::UpstreamToDownstream& upstream_to_downstream_interface) PURE;
};

/**
 * RouteConfigUpdatedCallback is used to notify an OnDemandRouteUpdate filter about completion of a
 * RouteConfig update. The filter (and the associated ActiveStream) where the original on-demand
 * request was originated can be destroyed before a response to an on-demand update request is
 * received and updates are propagated. To handle this:
 *
 * OnDemandRouteUpdate filter instance holds a RouteConfigUpdatedCallbackSharedPtr to a callback.
 * Envoy::Router::RdsRouteConfigProviderImpl holds a weak pointer to the RouteConfigUpdatedCallback
 * above in an Envoy::Router::UpdateOnDemandCallback struct
 *
 * In RdsRouteConfigProviderImpl::onConfigUpdate(), before invoking the callback, a check is made to
 * verify if the callback is still available.
 */
using RouteConfigUpdatedCallback = std::function<void(bool)>;
using RouteConfigUpdatedCallbackSharedPtr = std::shared_ptr<RouteConfigUpdatedCallback>;

// This class allows entities caching a route (e.g.) ActiveStream to delegate route clearing to xDS
// components.
class RouteCache {
public:
  virtual ~RouteCache() = default;

  // Returns true if the route cache currently has a cached route.
  virtual bool hasCachedRoute() const PURE;
  // Forces the route cache to refresh the cached route.
  virtual void refreshCachedRoute() PURE;
};

class RouteConfigUpdateRequester {
public:
  virtual ~RouteConfigUpdateRequester() = default;

  virtual void
  requestRouteConfigUpdate(RouteCache& route_cache,
                           Http::RouteConfigUpdatedCallbackSharedPtr route_config_updated_cb,
                           absl::optional<Router::ConfigConstSharedPtr> route_config,
                           Event::Dispatcher& dispatcher, RequestHeaderMap& request_headers) PURE;
  virtual void
  requestVhdsUpdate(const std::string& host_header, Event::Dispatcher& thread_local_dispatcher,
                    Http::RouteConfigUpdatedCallbackSharedPtr route_config_updated_cb) PURE;
  virtual void
  requestSrdsUpdate(RouteCache& route_cache, Router::ScopeKeyPtr scope_key,
                    Event::Dispatcher& thread_local_dispatcher,
                    Http::RouteConfigUpdatedCallbackSharedPtr route_config_updated_cb) PURE;
};

class RouteConfigUpdateRequesterFactory : public Config::UntypedFactory {
public:
  // UntypedFactory
  std::string category() const override { return "envoy.route_config_update_requester"; }

  virtual std::unique_ptr<RouteConfigUpdateRequester>
  createRouteConfigUpdateRequester(Router::RouteConfigProvider* route_config_provider) PURE;
  virtual std::unique_ptr<RouteConfigUpdateRequester>
  createRouteConfigUpdateRequester(Config::ConfigProvider* scoped_route_config_provider,
                                   OptRef<const Router::ScopeKeyBuilder> scope_key_builder) PURE;
};

class DownstreamStreamFilterCallbacks {
public:
  virtual ~DownstreamStreamFilterCallbacks() = default;

  /**
   * Sets the cached route for the current request to the passed-in RouteConstSharedPtr parameter.
   *
   * Similar to route(const Router::RouteCallback& cb), this route that is set will be
   * overridden by clearRouteCache() in subsequent filters. Usage is intended for filters at the end
   * of the filter chain.
   *
   * NOTE: Passing nullptr in as the route parameter is equivalent to route resolution being
   * attempted and failing to find a route. An example of when this happens is when
   * RouteConstSharedPtr route(const RouteCallback& cb, const Http::RequestHeaderMap& headers, const
   * StreamInfo::StreamInfo& stream_info, uint64_t random_value) returns nullptr during a
   * refreshCachedRoute. It is important to note that setRoute(nullptr) is different from a
   * clearRouteCache(), because clearRouteCache() wants route resolution to be attempted again.
   * clearRouteCache() achieves this by setting cached_route_ and cached_cluster_info_ to
   * absl::optional ptrs instead of null ptrs.
   */
  virtual void setRoute(Router::RouteConstSharedPtr route) PURE;

  /**
   * Invokes callback with a matched route, callback can choose to accept this route by returning
   * Router::RouteMatchStatus::Accept or continue route match from last matched route by returning
   * Router::RouteMatchStatus::Continue, if there are more routes available.
   *
   * Returns route accepted by the callback or nullptr if no match found or none of route is
   * accepted by the callback.
   *
   * NOTE: clearRouteCache() must be called before invoking this method otherwise cached route will
   * be returned directly to the caller and the callback will not be invoked.
   *
   * Currently a route callback's decision is overridden by clearRouteCache() / route() call in the
   * subsequent filters. We may want to persist callbacks so they always participate in later route
   * resolution or make it an independent entity like filters that gets called on route resolution.
   */
  virtual Router::RouteConstSharedPtr route(const Router::RouteCallback& cb) PURE;

  /**
   * Clears the route cache for the current request. This must be called when a filter has modified
   * the headers in a way that would affect routing.
   */
  virtual void clearRouteCache() PURE;

  /**
   * Refresh the target cluster but not the route cache. This is used when we want to change the
   * target cluster after modifying the request attributes.
   *
   * NOTE: this is suggested to replace clearRouteCache() if you only want to determine the target
   * cluster based on the latest request attributes that have been updated by the filters and do
   * not want to configure multiple similar routes at the route table.
   *
   * NOTE: this depends on the route cluster specifier to support the refreshRouteCluster()
   * method.
   */
  virtual void refreshRouteCluster() PURE;

  /**
   * Schedules a request for a RouteConfiguration update from the management server.
   * @param route_config_updated_cb callback to be called when the configuration update has been
   * propagated to the worker thread.
   */
  virtual void
  requestRouteConfigUpdate(RouteConfigUpdatedCallbackSharedPtr route_config_updated_cb) PURE;
};

/**
 * The stream filter callbacks are passed to all filters to use for writing response data and
 * interacting with the underlying stream in general.
 */
class StreamFilterCallbacks {
public:
  virtual ~StreamFilterCallbacks() = default;

  /**
   * @return OptRef<const Network::Connection> the downstream connection, or nullptr if there is
   * none.
   */
  virtual OptRef<const Network::Connection> connection() PURE;

  /**
   * @return Event::Dispatcher& the thread local dispatcher for allocating timers, etc.
   */
  virtual Event::Dispatcher& dispatcher() PURE;

  /**
   * Reset the underlying stream.
   */
  virtual void
  resetStream(Http::StreamResetReason reset_reason = Http::StreamResetReason::LocalReset,
              absl::string_view transport_failure_reason = "") PURE;

  /**
   * Returns the route for the current request. The assumption is that the implementation can do
   * caching where applicable to avoid multiple lookups. If a filter has modified the headers in
   * a way that affects routing, clearRouteCache() must be called to clear the cache.
   */
  virtual Router::RouteConstSharedPtr route() PURE;

  /**
   * Returns the clusterInfo for the cached route.
   * This method is to avoid multiple look ups in the filter chain, it also provides a consistent
   * view of clusterInfo after a route is picked/repicked.
   * NOTE: Cached clusterInfo and route will be updated the same time.
   */
  virtual Upstream::ClusterInfoConstSharedPtr clusterInfo() PURE;

  /**
   * @return uint64_t the ID of the originating stream for logging purposes.
   */
  virtual uint64_t streamId() const PURE;

  /**
   * @return streamInfo for logging purposes. Individual filter may add specific information to be
   * put into the access log.
   */
  virtual StreamInfo::StreamInfo& streamInfo() PURE;

  /**
   * @return span context used for tracing purposes. Individual filters may add or modify
   *              information in the span context.
   */
  virtual Tracing::Span& activeSpan() PURE;

  /**
   * @return tracing configuration if present.
   */
  virtual OptRef<const Tracing::Config> tracingConfig() const PURE;

  /**
   * @return the ScopeTrackedObject for this stream.
   */
  virtual const ScopeTrackedObject& scope() PURE;

  /**
   * Should be used when we continue processing a request or response by invoking a filter directly
   * from an asynchronous callback to restore crash context. If not explicitly used by the filter
   * itself, this gets invoked in ActiveStreamFilterBase::commonContinue().
   *
   * @param tracked_object_stack ScopeTrackedObjectStack where relevant ScopeTrackedObjects will be
   * added to.
   */
  virtual void restoreContextOnContinue(ScopeTrackedObjectStack& tracked_object_stack) PURE;

  /**
   * Called when filter activity indicates that the stream idle timeout should be reset.
   */
  virtual void resetIdleTimer() PURE;

  /**
   * This is a helper to get the route's per-filter config if it exists, otherwise the virtual
   * host's. Or nullptr if none of them exist.
   */
  virtual const Router::RouteSpecificFilterConfig* mostSpecificPerFilterConfig() const PURE;

  /**
   * Return all the available per route filter configs. The configs is in order of specificity.
   * That means that the config from a route configuration will be first, then the config from a
   * virtual host, then the config from a route.
   */
  virtual Router::RouteSpecificFilterConfigs perFilterConfigs() const PURE;

  /**
   * Return the HTTP/1 stream encoder options if applicable. If the stream is not HTTP/1 returns
   * absl::nullopt.
   */
  virtual Http1StreamEncoderOptionsOptRef http1StreamEncoderOptions() PURE;

  /**
   * Return a handle to the upstream callbacks. This is valid for upstream HTTP filters, and nullopt
   * for downstream HTTP filters.
   */
  virtual OptRef<UpstreamStreamFilterCallbacks> upstreamCallbacks() PURE;

  /**
   * Return a handle to the downstream callbacks. This is valid for downstream HTTP filters, and
   * nullopt for upstream HTTP filters.
   */
  virtual OptRef<DownstreamStreamFilterCallbacks> downstreamCallbacks() PURE;

  /**
   * @return absl::string_view the name of the filter as configured in the filter chain.
   */
  virtual absl::string_view filterConfigName() const PURE;

  /**
   * The downstream request headers if present.
   */
  virtual RequestHeaderMapOptRef requestHeaders() PURE;

  /**
   * The downstream request trailers if present.
   */
  virtual RequestTrailerMapOptRef requestTrailers() PURE;

  /**
   * Retrieves a pointer to the continue headers if present.
   */
  virtual ResponseHeaderMapOptRef informationalHeaders() PURE;

  /**
   * Retrieves a pointer to the response headers if present.
   * Note that response headers might be set multiple times (e.g. if a local reply is issued after
   * headers have been received but before headers have been encoded), so it is not safe in general
   * to assume that any set of headers will be valid for the duration of the stream.
   */
  virtual ResponseHeaderMapOptRef responseHeaders() PURE;

  /**
   * Retrieves a pointer to the last response trailers if present.
   * Note that response headers might be set multiple times (e.g. if a local reply is issued after
   * headers have been received but before headers have been encoded), so it is not safe in general
   * to assume that any set of headers will be valid for the duration of the stream.
   */
  virtual ResponseTrailerMapOptRef responseTrailers() PURE;
};

/**
 * Stream decoder filter callbacks add additional callbacks that allow a
 * decoding filter to restart decoding if they decide to hold data (e.g. for
 * buffering or rate limiting).
 */
class StreamDecoderFilterCallbacks : public virtual StreamFilterCallbacks {
public:
  /**
   * Continue iterating through the filter chain with buffered headers and body data. This routine
   * can only be called if the filter has previously returned StopIteration from decodeHeaders()
   * AND one of StopIterationAndBuffer, StopIterationAndWatermark, or StopIterationNoBuffer
   * from each previous call to decodeData().
   *
   * The connection manager will dispatch headers and any buffered body data to the
   * next filter in the chain. Further note that if the request is not complete, this filter will
   * still receive decodeData() calls and must return an appropriate status code depending on what
   * the filter needs to do.
   */
  virtual void continueDecoding() PURE;

  /**
   * @return const Buffer::Instance* the currently buffered data as buffered by this filter or
   *         previous ones in the filter chain. May be nullptr if nothing has been buffered yet.
   */
  virtual const Buffer::Instance* decodingBuffer() PURE;

  /**
   * Allows modifying the decoding buffer. May only be called before any data has been continued
   * past the calling filter.
   */
  virtual void modifyDecodingBuffer(std::function<void(Buffer::Instance&)> callback) PURE;

  /**
   * Add buffered body data. This method is used in advanced cases where returning
   * StopIterationAndBuffer from decodeData() is not sufficient.
   *
   * 1) If a headers only request needs to be turned into a request with a body, this method can
   * be called to add body in the decodeHeaders() callback. Subsequent filters will receive
   * decodeHeaders(..., false) followed by decodeData(..., true). This works both in the direct
   * iteration as well as the continuation case.
   *
   * 2) If a filter is going to look at all buffered data from within a data callback with end
   * stream set, this method can be called to immediately buffer the data. This avoids having
   * to deal with the existing buffered data and the data from the current callback.
   *
   * 3) If additional buffered body data needs to be added by a filter before continuation of data
   * to further filters (outside of callback context).
   *
   * 4) If additional data needs to be added in the decodeTrailers() callback, this method can be
   * called in the context of the callback. All further filters will receive decodeData(..., false)
   * followed by decodeTrailers(). However if the iteration is stopped, the added data will
   * buffered, so that the further filters will not receive decodeData() before decodeHeaders().
   *
   * It is an error to call this method in any other case.
   *
   * See also injectDecodedDataToFilterChain() for a different way of passing data to further
   * filters and also how the two methods are different.
   *
   * @param data Buffer::Instance supplies the data to be decoded.
   * @param streaming_filter boolean supplies if this filter streams data or buffers the full body.
   */
  virtual void addDecodedData(Buffer::Instance& data, bool streaming_filter) PURE;

  /**
   * Decode data directly to subsequent filters in the filter chain. This method is used in
   * advanced cases in which a filter needs full control over how subsequent filters view data,
   * and does not want to make use of HTTP connection manager buffering. Using this method allows
   * a filter to buffer data (or not) and then periodically inject data to subsequent filters,
   * indicating end_stream at an appropriate time. This can be used to implement rate limiting,
   * periodic data emission, etc.
   *
   * This method should only be called outside of callback context. I.e., do not call this method
   * from within a filter's decodeData() call.
   *
   * When using this callback, filters should generally only return
   * FilterDataStatus::StopIterationNoBuffer from their decodeData() call, since use of this method
   * indicates that a filter does not wish to participate in standard HTTP connection manager
   * buffering and continuation and will perform any necessary buffering and continuation on its
   * own.
   *
   * This callback is different from addDecodedData() in that the specified data and end_stream
   * status will be propagated directly to further filters in the filter chain. This is different
   * from addDecodedData() where data is added to the HTTP connection manager's buffered data with
   * the assumption that standard HTTP connection manager buffering and continuation are being used.
   */
  virtual void injectDecodedDataToFilterChain(Buffer::Instance& data, bool end_stream) PURE;

  /**
   * Adds decoded trailers. May only be called in decodeData when end_stream is set to true.
   * If called in any other context, an assertion will be triggered.
   *
   * When called in decodeData, the trailers map will be initialized to an empty map and returned by
   * reference. Calling this function more than once is invalid.
   *
   * @return a reference to the newly created trailers map.
   */
  virtual RequestTrailerMap& addDecodedTrailers() PURE;

  /**
   * Attempts to create a locally generated response using the provided response_code and body_text
   * parameters. If the request was a gRPC request the local reply will be encoded as a gRPC
   * response with a 200 HTTP response code and grpc-status and grpc-message headers mapped from the
   * provided parameters.
   *
   * If a response has already started (e.g. if the router calls sendLocalReply after encoding
   * headers) this will either ship the reply directly to the downstream codec, or reset the stream.
   *
   * @param response_code supplies the HTTP response code.
   * @param body_text supplies the optional body text which is sent using the text/plain content
   *                  type, or encoded in the grpc-message header.
   * @param modify_headers supplies an optional callback function that can modify the
   *                       response headers.
   * @param grpc_status the gRPC status code to override the httpToGrpcStatus mapping with.
   * @param details a string detailing why this local reply was sent.
   */
  virtual void sendLocalReply(Code response_code, absl::string_view body_text,
                              std::function<void(ResponseHeaderMap& headers)> modify_headers,
                              const absl::optional<Grpc::Status::GrpcStatus> grpc_status,
                              absl::string_view details) PURE;

  /**
   * Attempt to send GOAWAY and close the connection, and no filter chain will move forward.
   */
  virtual void sendGoAwayAndClose() PURE;

  /**
   * Adds decoded metadata. This function can only be called in
   * StreamDecoderFilter::decodeHeaders/Data/Trailers(). Do not call in
   * StreamDecoderFilter::decodeMetadata().
   *
   * @return a reference to metadata map vector, where new metadata map can be added.
   */
  virtual MetadataMapVector& addDecodedMetadata() PURE;

  /**
   * Called with 1xx headers to be encoded.
   *
   * Currently supported codes for this function include 100.
   *
   * This is not folded into encodeHeaders because most Envoy users and filters will not be proxying
   * 1xx headers and with it split out, can ignore the complexity of multiple encodeHeaders calls.
   *
   * This is currently only called once per request but implementations should
   * handle multiple calls as multiple 1xx headers are legal.
   *
   * @param headers supplies the headers to be encoded.
   */
  virtual void encode1xxHeaders(ResponseHeaderMapPtr&& headers) PURE;

  /**
   * Called with headers to be encoded, optionally indicating end of stream.
   *
   * The connection manager inspects certain pseudo headers that are not actually sent downstream.
   * - See source/common/http/headers.h
   *
   * The only 1xx that may be provided to encodeHeaders() is a 101 upgrade, which will be the final
   * encodeHeaders() for a response.
   *
   * @param headers supplies the headers to be encoded.
   * @param end_stream supplies whether this is a header only request/response.
   * @param details supplies the details of why this response was sent.
   */
  virtual void encodeHeaders(ResponseHeaderMapPtr&& headers, bool end_stream,
                             absl::string_view details) PURE;

  /**
   * Called with data to be encoded, optionally indicating end of stream.
   * @param data supplies the data to be encoded.
   * @param end_stream supplies whether this is the last data frame.
   */
  virtual void encodeData(Buffer::Instance& data, bool end_stream) PURE;

  /**
   * Called with trailers to be encoded. This implicitly ends the stream.
   * @param trailers supplies the trailers to encode.
   */
  virtual void encodeTrailers(ResponseTrailerMapPtr&& trailers) PURE;

  /**
   * Called with metadata to be encoded.
   *
   * @param metadata_map supplies the unique_ptr of the metadata to be encoded.
   */
  virtual void encodeMetadata(MetadataMapPtr&& metadata_map) PURE;

  /**
   * Called when the buffer for a decoder filter or any buffers the filter sends data to go over
   * their high watermark.
   *
   * In the case of a filter such as the router filter, which spills into multiple buffers (codec,
   * connection etc.) this may be called multiple times. Any such filter is responsible for calling
   * the low watermark callbacks an equal number of times as the respective buffers are drained.
   */
  virtual void onDecoderFilterAboveWriteBufferHighWatermark() PURE;

  /**
   * Called when a decoder filter or any buffers the filter sends data to go from over its high
   * watermark to under its low watermark.
   */
  virtual void onDecoderFilterBelowWriteBufferLowWatermark() PURE;

  /**
   * This routine can be called by a filter to subscribe to watermark events on the downstream
   * stream and downstream connection.
   *
   * Immediately after subscribing, the filter will get a high watermark callback for each
   * outstanding backed up buffer.
   */
  virtual void addDownstreamWatermarkCallbacks(DownstreamWatermarkCallbacks& callbacks) PURE;

  /**
   * This routine can be called by a filter to stop subscribing to watermark events on the
   * downstream stream and downstream connection.
   *
   * It is not safe to call this from under the stack of a DownstreamWatermarkCallbacks callback.
   */
  virtual void removeDownstreamWatermarkCallbacks(DownstreamWatermarkCallbacks& callbacks) PURE;

  /**
   * This routine may be called to change the buffer limit for decoder filters.
   *
   * It is recommended (but not required) that filters calling this function should
   * generally only perform increases to the buffer limit, to avoid potentially
   * conflicting with the buffer requirements of other filters in the chain, i.e.
   *
   * if (desired_limit > decoderBufferLimit()) {setDecoderBufferLimit(desired_limit);}
   *
   * @param limit supplies the desired buffer limit.
   */
  virtual void setDecoderBufferLimit(uint32_t limit) PURE;

  /**
   * This routine returns the current buffer limit for decoder filters. Filters should abide by
   * this limit or change it via setDecoderBufferLimit.
   * A buffer limit of 0 bytes indicates no limits are applied.
   *
   * @return the buffer limit the filter should apply.
   */
  virtual uint32_t decoderBufferLimit() PURE;

  /**
   * @return the account, if any, used by this stream.
   */
  virtual Buffer::BufferMemoryAccountSharedPtr account() const PURE;

  /**
   * Takes a stream, and acts as if the headers are newly arrived.
   * On success, this will result in a creating a new filter chain and likely
   * upstream request associated with the original downstream stream. On
   * failure, if the preconditions outlined below are not met, the caller is
   * responsible for handling or terminating the original stream.
   *
   * This is currently limited to
   *   - streams which are completely read
   *   - streams which do not have a request body.
   *
   * Note that HttpConnectionManager sanitization will *not* be performed on the
   * recreated stream, as it is assumed that sanitization has already been done.
   *
   * @param original_response_headers Headers used for logging in the access logs and for charging
   * stats. Ignored if null.
   */
  virtual bool recreateStream(const ResponseHeaderMap* original_response_headers) PURE;

  /**
   * Adds socket options to be applied to any connections used for upstream requests. Note that
   * unique values for the options will likely lead to many connection pools being created. The
   * added options are appended to any previously added.
   *
   * @param options The options to be added.
   */
  virtual void addUpstreamSocketOptions(const Network::Socket::OptionsSharedPtr& options) PURE;

  /**
   * @return The socket options to be applied to the upstream request.
   */
  virtual Network::Socket::OptionsSharedPtr getUpstreamSocketOptions() const PURE;

  /**
   * Set override host to be used by the upstream load balancing. If the target host exists in the
   * host list of the routed cluster, the host should be selected first.
   * @param host The override host address.
   */
  virtual void setUpstreamOverrideHost(Upstream::LoadBalancerContext::OverrideHost) PURE;

  /**
   * @return absl::optional<absl::string_view> optional override host for the upstream
   * load balancing.
   */
  virtual absl::optional<Upstream::LoadBalancerContext::OverrideHost>
  upstreamOverrideHost() const PURE;

  /**
   * @return true if the filter should shed load based on the system pressure, typically memory.
   */
  virtual bool shouldLoadShed() const PURE;
};

/**
 * Common base class for both decoder and encoder filters. Functions here are related to the
 * lifecycle of a filter. Currently the life cycle is as follows:
 * - All filters receive onStreamComplete()
 * - All log handlers receive final log()
 * - All filters receive onDestroy()
 *
 * This means:
 * - onStreamComplete can be used to make state changes that are intended to appear in the final
 * access logs (like streamInfo().dynamicMetadata() or streamInfo().filterState()).
 * - onDestroy is used to cleanup all pending filter resources like pending http requests and
 * timers.
 */
class StreamFilterBase {
public:
  virtual ~StreamFilterBase() = default;

  /**
   * This routine is called before the access log handlers' final log() is called. Filters can use
   * this callback to enrich the data passed in to the log handlers.
   */
  virtual void onStreamComplete() {}

  /**
   * This routine is called prior to a filter being destroyed. This may happen after normal stream
   * finish (both downstream and upstream) or due to reset. Every filter is responsible for making
   * sure that any async events are cleaned up in the context of this routine. This includes timers,
   * network calls, etc. The reason there is an onDestroy() method vs. doing this type of cleanup
   * in the destructor is due to the deferred deletion model that Envoy uses to avoid stack unwind
   * complications. Filters must not invoke either encoder or decoder filter callbacks after having
   * onDestroy() invoked. Filters that cross-register as access log handlers receive log() before
   * onDestroy().
   */
  virtual void onDestroy() PURE;

  /**
   * Called when a match result occurs that isn't handled by the filter manager.
   * @param action the resulting match action
   */
  virtual void onMatchCallback(const Matcher::Action&) {}

  struct LocalReplyData {
    // The error code which (barring reset) will be sent to the client.
    Http::Code code_;
    // The gRPC status set in local reply.
    absl::optional<Grpc::Status::GrpcStatus> grpc_status_;
    // The details of why a local reply is being sent.
    absl::string_view details_;
    // True if a reset will occur rather than the local reply (some prior filter
    // has returned ContinueAndResetStream)
    bool reset_imminent_;
  };

  /**
   * Called after sendLocalReply is called, and before any local reply is
   * serialized either to filters, or downstream.
   * This will be called on both encoder and decoder filters starting at the
   * terminal filter (generally the router filter) and working towards the first filter configured.
   *
   * Note that in some circumstances, onLocalReply may be called more than once
   * for a given stream, because it is possible that a filter call
   * sendLocalReply while processing the original local reply response.
   *
   * Filters implementing onLocalReply are responsible for never calling sendLocalReply
   * from onLocalReply, as that has the potential for looping.
   *
   * @param data data associated with the sendLocalReply call.
   * @param LocalErrorStatus the action to take after onLocalReply completes.
   */
  virtual LocalErrorStatus onLocalReply(const LocalReplyData&) {
    return LocalErrorStatus::Continue;
  }
};

/**
 * Stream decoder filter interface.
 */
class StreamDecoderFilter : public virtual StreamFilterBase {
public:
  /**
   * Called with decoded headers, optionally indicating end of stream.
   * @param headers supplies the decoded headers map.
   * @param end_stream supplies whether this is a header only request/response.
   * @return FilterHeadersStatus determines how filter chain iteration proceeds.
   */
  virtual FilterHeadersStatus decodeHeaders(RequestHeaderMap& headers, bool end_stream) PURE;

  /**
   * Called with a decoded data frame.
   * @param data supplies the decoded data.
   * @param end_stream supplies whether this is the last data frame.
   * Further note that end_stream is only true if there are no trailers.
   * @return FilterDataStatus determines how filter chain iteration proceeds.
   */
  virtual FilterDataStatus decodeData(Buffer::Instance& data, bool end_stream) PURE;

  /**
   * Called with decoded trailers, implicitly ending the stream.
   * @param trailers supplies the decoded trailers.
   */
  virtual FilterTrailersStatus decodeTrailers(RequestTrailerMap& trailers) PURE;

  /**
   * Called with decoded metadata. Add new metadata to metadata_map directly. Do not call
   * StreamDecoderFilterCallbacks::addDecodedMetadata() to add new metadata.
   *
   * Note: decodeMetadata() currently cannot stop the filter iteration, and always returns Continue.
   * That means metadata will go through the complete filter chain at once, even if the other frame
   * types return StopIteration. If metadata should not pass through all filters at once, users
   * should consider using StopAllIterationAndBuffer or StopAllIterationAndWatermark in
   * decodeHeaders() to prevent metadata passing to the following filters.
   *
   * @param metadata_map supplies the decoded metadata.
   */
  virtual FilterMetadataStatus decodeMetadata(MetadataMap& /* metadata_map */) {
    return Http::FilterMetadataStatus::Continue;
  }

  /**
   * Called by the filter manager once to initialize the filter decoder callbacks that the
   * filter should use. Callbacks will not be invoked by the filter after onDestroy() is called.
   */
  virtual void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) PURE;

  /**
   * Called at the end of the stream, when all data has been decoded.
   */
  virtual void decodeComplete() {}
};

using StreamDecoderFilterSharedPtr = std::shared_ptr<StreamDecoderFilter>;

/**
 * Stream encoder filter callbacks add additional callbacks that allow a encoding filter to restart
 * encoding if they decide to hold data (e.g. for buffering or rate limiting).
 */
class StreamEncoderFilterCallbacks : public virtual StreamFilterCallbacks {
public:
  /**
   * Continue iterating through the filter chain with buffered headers and body data. This routine
   * can only be called if the filter has previously returned StopIteration from encodeHeaders() AND
   * one of StopIterationAndBuffer, StopIterationAndWatermark, or StopIterationNoBuffer
   * from each previous call to encodeData().
   *
   * The connection manager will dispatch headers and any buffered body data to the next filter in
   * the chain. Further note that if the response is not complete, this filter will still receive
   * encodeData() calls and must return an appropriate status code depending on what the filter
   * needs to do.
   */
  virtual void continueEncoding() PURE;

  /**
   * @return const Buffer::Instance* the currently buffered data as buffered by this filter or
   *         previous ones in the filter chain. May be nullptr if nothing has been buffered yet.
   */
  virtual const Buffer::Instance* encodingBuffer() PURE;

  /**
   * Allows modifying the encoding buffer. May only be called before any data has been continued
   * past the calling filter.
   */
  virtual void modifyEncodingBuffer(std::function<void(Buffer::Instance&)> callback) PURE;

  /**
   * Add buffered body data. This method is used in advanced cases where returning
   * StopIterationAndBuffer from encodeData() is not sufficient.
   *
   * 1) If a headers only response needs to be turned into a response with a body, this method can
   * be called to add body in the encodeHeaders() callback. Subsequent filters will receive
   * encodeHeaders(..., false) followed by encodeData(..., true). This works both in the direct
   * iteration as well as the continuation case.
   *
   * 2) If a filter is going to look at all buffered data from within a data callback with end
   * stream set, this method can be called to immediately buffer the data. This avoids having
   * to deal with the existing buffered data and the data from the current callback.
   *
   * 3) If additional buffered body data needs to be added by a filter before continuation of data
   * to further filters (outside of callback context).
   *
   * 4) If additional data needs to be added in the encodeTrailers() callback, this method can be
   * called in the context of the callback. All further filters will receive encodeData(..., false)
   * followed by encodeTrailers(). However if the iteration is stopped, the added data will
   * buffered, so that the further filters will not receive encodeData() before encodeHeaders().
   *
   * It is an error to call this method in any other case.
   *
   * See also injectEncodedDataToFilterChain() for a different way of passing data to further
   * filters and also how the two methods are different.
   *
   * @param data Buffer::Instance supplies the data to be encoded.
   * @param streaming_filter boolean supplies if this filter streams data or buffers the full body.
   */
  virtual void addEncodedData(Buffer::Instance& data, bool streaming_filter) PURE;

  /**
   * Encode data directly to subsequent filters in the filter chain. This method is used in
   * advanced cases in which a filter needs full control over how subsequent filters view data,
   * and does not want to make use of HTTP connection manager buffering. Using this method allows
   * a filter to buffer data (or not) and then periodically inject data to subsequent filters,
   * indicating end_stream at an appropriate time. This can be used to implement rate limiting,
   * periodic data emission, etc.
   *
   * This method should only be called outside of callback context. I.e., do not call this method
   * from within a filter's encodeData() call.
   *
   * When using this callback, filters should generally only return
   * FilterDataStatus::StopIterationNoBuffer from their encodeData() call, since use of this method
   * indicates that a filter does not wish to participate in standard HTTP connection manager
   * buffering and continuation and will perform any necessary buffering and continuation on its
   * own.
   *
   * This callback is different from addEncodedData() in that the specified data and end_stream
   * status will be propagated directly to further filters in the filter chain. This is different
   * from addEncodedData() where data is added to the HTTP connection manager's buffered data with
   * the assumption that standard HTTP connection manager buffering and continuation are being used.
   */
  virtual void injectEncodedDataToFilterChain(Buffer::Instance& data, bool end_stream) PURE;

  /**
   * Adds encoded trailers. May only be called in encodeData when end_stream is set to true.
   * If called in any other context, an assertion will be triggered.
   *
   * When called in encodeData, the trailers map will be initialized to an empty map and returned by
   * reference. Calling this function more than once is invalid.
   *
   * @return a reference to the newly created trailers map.
   */
  virtual ResponseTrailerMap& addEncodedTrailers() PURE;

  /**
   * Attempts to create a locally generated response using the provided response_code and body_text
   * parameters. If the request was a gRPC request the local reply will be encoded as a gRPC
   * response with a 200 HTTP response code and grpc-status and grpc-message headers mapped from the
   * provided parameters.
   *
   * If a response has already started (e.g. if the router calls sendLocalReply after encoding
   * headers) this will either ship the reply directly to the downstream codec, or reset the stream.
   *
   * @param response_code supplies the HTTP response code.
   * @param body_text supplies the optional body text which is sent using the text/plain content
   *                  type, or encoded in the grpc-message header.
   * @param modify_headers supplies an optional callback function that can modify the
   *                       response headers.
   * @param grpc_status the gRPC status code to override the httpToGrpcStatus mapping with.
   * @param details a string detailing why this local reply was sent.
   */
  virtual void sendLocalReply(Code response_code, absl::string_view body_text,
                              std::function<void(ResponseHeaderMap& headers)> modify_headers,
                              const absl::optional<Grpc::Status::GrpcStatus> grpc_status,
                              absl::string_view details) PURE;
  /**
   * Adds new metadata to be encoded.
   *
   * @param metadata_map supplies the unique_ptr of the metadata to be encoded.
   */
  virtual void addEncodedMetadata(MetadataMapPtr&& metadata_map) PURE;

  /**
   * Called when an encoder filter goes over its high watermark.
   */
  virtual void onEncoderFilterAboveWriteBufferHighWatermark() PURE;

  /**
   * Called when a encoder filter goes from over its high watermark to under its low watermark.
   */
  virtual void onEncoderFilterBelowWriteBufferLowWatermark() PURE;

  /**
   * This routine may be called to change the buffer limit for encoder filters.
   *
   * It is recommended (but not required) that filters calling this function should
   * generally only perform increases to the buffer limit, to avoid potentially
   * conflicting with the buffer requirements of other filters in the chain, i.e.
   *
   * if (desired_limit > encoderBufferLimit()) {setEncoderBufferLimit(desired_limit);}
   *
   * @param limit supplies the desired buffer limit.
   */
  virtual void setEncoderBufferLimit(uint32_t limit) PURE;

  /**
   * This routine returns the current buffer limit for encoder filters. Filters should abide by
   * this limit or change it via setEncoderBufferLimit.
   * A buffer limit of 0 bytes indicates no limits are applied.
   *
   * @return the buffer limit the filter should apply.
   */
  virtual uint32_t encoderBufferLimit() PURE;
};

/**
 * Stream encoder filter interface.
 */
class StreamEncoderFilter : public virtual StreamFilterBase {
public:
  /**
   * Called with supported 1xx headers.
   *
   * This is not folded into encodeHeaders because most Envoy users and filters
   * will not be proxying 1xxs and with it split out, can ignore the
   * complexity of multiple encodeHeaders calls.
   *
   * This will only be invoked once per request.
   *
   * @param headers supplies the 1xx response headers to be encoded.
   * @return Filter1xxHeadersStatus determines how filter chain iteration proceeds.
   *
   */
  virtual Filter1xxHeadersStatus encode1xxHeaders(ResponseHeaderMap& headers) PURE;

  /**
   * Called with headers to be encoded, optionally indicating end of stream.
   *
   * The only 1xx that may be provided to encodeHeaders() is a 101 upgrade, which will be the final
   * encodeHeaders() for a response.
   *
   * @param headers supplies the headers to be encoded.
   * @param end_stream supplies whether this is a header only request/response.
   * @return FilterHeadersStatus determines how filter chain iteration proceeds.
   */
  virtual FilterHeadersStatus encodeHeaders(ResponseHeaderMap& headers, bool end_stream) PURE;

  /**
   * Called with data to be encoded, optionally indicating end of stream.
   * @param data supplies the data to be encoded.
   * @param end_stream supplies whether this is the last data frame.
   * Further note that end_stream is only true if there are no trailers.
   * @return FilterDataStatus determines how filter chain iteration proceeds.
   */
  virtual FilterDataStatus encodeData(Buffer::Instance& data, bool end_stream) PURE;

  /**
   * Called with trailers to be encoded, implicitly ending the stream.
   * @param trailers supplies the trailers to be encoded.
   */
  virtual FilterTrailersStatus encodeTrailers(ResponseTrailerMap& trailers) PURE;

  /**
   * Called with metadata to be encoded. New metadata should be added directly to metadata_map. DO
   * NOT call StreamDecoderFilterCallbacks::encodeMetadata() interface to add new metadata.
   *
   * @param metadata_map supplies the metadata to be encoded.
   * @return FilterMetadataStatus, which currently is always FilterMetadataStatus::Continue;
   */
  virtual FilterMetadataStatus encodeMetadata(MetadataMap& metadata_map) PURE;

  /**
   * Called by the filter manager once to initialize the filter callbacks that the filter should
   * use. Callbacks will not be invoked by the filter after onDestroy() is called.
   */
  virtual void setEncoderFilterCallbacks(StreamEncoderFilterCallbacks& callbacks) PURE;

  /**
   * Called at the end of the stream, when all data has been encoded.
   */
  virtual void encodeComplete() {}
};

using StreamEncoderFilterSharedPtr = std::shared_ptr<StreamEncoderFilter>;

/**
 * A filter that handles both encoding and decoding.
 */
class StreamFilter : public virtual StreamDecoderFilter, public virtual StreamEncoderFilter {};

using StreamFilterSharedPtr = std::shared_ptr<StreamFilter>;

class HttpMatchingData {
public:
  static absl::string_view name() { return "http"; }

  virtual ~HttpMatchingData() = default;

  virtual RequestHeaderMapOptConstRef requestHeaders() const PURE;
  virtual RequestTrailerMapOptConstRef requestTrailers() const PURE;
  virtual ResponseHeaderMapOptConstRef responseHeaders() const PURE;
  virtual ResponseTrailerMapOptConstRef responseTrailers() const PURE;
  virtual const StreamInfo::StreamInfo& streamInfo() const PURE;
  virtual const Network::ConnectionInfoProvider& connectionInfoProvider() const PURE;

  const StreamInfo::FilterState& filterState() const { return streamInfo().filterState(); }
  const envoy::config::core::v3::Metadata& metadata() const {
    return streamInfo().dynamicMetadata();
  }

  const Network::Address::Instance& localAddress() const {
    return *connectionInfoProvider().localAddress();
  }

  const Network::Address::Instance& remoteAddress() const {
    return *connectionInfoProvider().remoteAddress();
  }

  Ssl::ConnectionInfoConstSharedPtr ssl() const { return connectionInfoProvider().sslConnection(); }
};

/**
 * These callbacks are provided by the connection manager to the factory so that the factory can
 * build the filter chain in an application specific way.
 */
class FilterChainFactoryCallbacks {
public:
  virtual ~FilterChainFactoryCallbacks() = default;

  /**
   * Add a decoder filter that is used when reading stream data.
   * @param filter supplies the filter to add.
   */
  virtual void addStreamDecoderFilter(Http::StreamDecoderFilterSharedPtr filter) PURE;

  /**
   * Add an encoder filter that is used when writing stream data.
   * @param filter supplies the filter to add.
   */
  virtual void addStreamEncoderFilter(Http::StreamEncoderFilterSharedPtr filter) PURE;

  /**
   * Add a decoder/encoder filter that is used both when reading and writing stream data.
   * @param filter supplies the filter to add.
   */
  virtual void addStreamFilter(Http::StreamFilterSharedPtr filter) PURE;

  /**
   * Add an access log handler that is called when the stream is destroyed.
   * @param handler supplies the handler to add.
   */
  virtual void addAccessLogHandler(AccessLog::InstanceSharedPtr handler) PURE;

  /**
   * Allows filters to access the thread local dispatcher.
   * @param return the worker thread's dispatcher.
   */
  virtual Event::Dispatcher& dispatcher() PURE;
};
} // namespace Http
} // namespace Envoy
