botrx_polyfill()
botrx_addEventListener(window, "load", botrx_trace)
botrx_addEventListener(window, "beforeunload", function () {
    botrx_stats_update(true)
})

/**
 * botrx_trace
 */
function botrx_trace() {
    if (!window.botrx_valid || !window.botrx_stats) {
        return
    }

    all_links = document.getElementsByTagName("a")
    for (var i = 0; i < all_links.length; i++) {

        // SVG and other objects using the A tag should not be considered
        var link = all_links[i]
        if (typeof link.href != "string") {
            continue
        }

        var external = (link.hostname == location.hostname) ? 0 : 1
        if (external) {
            // link.addEventListener("click", botrx_trace_handler)
            botrx_addEventListener(link, "click", botrx_trace_handler)
        }
    }
}

function botrx_trace_handler(e) {
    e = e ? e : window.event
    node = ("undefined" != typeof e.target) ? e.target : (("undefined" != typeof e.srcElement) ? e.srcElement : false)
    if (!node) {
        return false
    }

    // Safari bug
    if (3 == node.nodeType) {
        node = node.parentNode
    }

    parent_node = node.parentNode
    resource_url = ''

    switch (node.nodeName) {
        case 'FORM':
            if ("undefined" != typeof node.action && node.action) {
                resource_url = node.action
            }
            break

        case 'INPUT':
            while ("undefined" != typeof parent_node && parent_node.nodeName != "FORM" && parent_node.nodeName != "BODY") {
                parent_node = parent_node.parentNode
            }
            if ("undefined" != typeof parent_node.action && parent_node.action) {
                resource_url = parent_node.action
                break
            }

            default:
                if ("A" != node.nodeName) {
                    while ("undefined" != typeof node.parentNode && null != node.parentNode && "A" != node.nodeName && "BODY" != node.nodeName) {
                        node = node.parentNode
                    }
                }

                // Anchor in the same page
                if ("undefined" != typeof node.hash && node.hash && node.hostname == location.hostname) {
                    resource_url = node.hash
                } else if ("undefined" != typeof node.href && node.href.indexOf('javascript:') == -1) {
                    resource_url = node.href
                }
    }

    if (window.botrx_stats) {
        botrx_stats.outbound_resource = resource_url
    }
    if (window.botrx_debug) {
        console.log('[botrx_trace_handler] outbound_resource: ' + resource_url)
    }

    return true
}

/**
 * botrx_stats_update
 */
function botrx_stats_update(leave_page) {
    if (!window.botrx_valid || !window.botrx_stats) {
        return
    }

    var _st = window.botrx_stats
    leave_page = (leave_page == undefined || leave_page == null) ? 0 : (leave_page ? 1 : 0)

    // find dap_session_id
    var dap_session_id = /dap_session_id=(.*?)(;|$)/.exec(document.cookie)
    if (dap_session_id && dap_session_id[1]) {
        dap_session_id = dap_session_id[1]
    } else {
        dap_session_id = _st.dap_session_id || ''
    }

    // find dap_fp
    var dap_fp = /dap_fp=(.*?)(;|$)/.exec(document.cookie)
    if (dap_fp && dap_fp[1]) {
        dap_fp = dap_fp[1]
    } else {
        dap_fp = _st.dap_fp || ''
    }

    // calculate time
    var now = new Date().getTime(),
        response_end_time = _st.response_end_time = get_response_end(),
        corejs_start = _st.corejs_start_time,
        corejs_end = _st.corejs_end_time,
        corejs_speed = _st.corejs_speed = _st.corejs_finish * 1000, // seond -> millisecond
        corejs_load = _st.timing ? _st.timing.corejs_load : (corejs_start - response_end_time)
    var is_valid_time = response_end_time > 0 && corejs_start > 0 && corejs_end > 0

    var timestamp_out = leave_page ? now : 0
    var page_stay = leave_page && is_valid_time ? now - response_end_time : 0
    if (page_stay >= 600000) { // max is 10 minutes
        page_stay = 600000
    }

    // prepare data
    var server_latency = get_server_latency(),
        page_speed = get_page_speed()
    var data = {
        _ajax_nonce: botrx_ajax_obj.nonce,
        action: 'botrx_stats_update',
        lp: leave_page,
        ri: _st.row_id,
        fp: window.btoa(dap_fp),
        si: window.btoa(dap_session_id),
        ou: timestamp_out,
        tl: window.btoa(encodeURIComponent(document.title|| '')),
        or: window.btoa(_st.outbound_resource || ''),
        sl: server_latency,
        ps: page_speed,
        pt: page_stay,
        cs: corejs_speed
    }
    if (window.botrx_debug) {
        var title = leave_page ? 'botrx_stats_leave' : 'botrx_stats_update' // botrx_stats_new
        console.log('[' + title + '] row_id=' + _st.row_id + ', server_latency=' + server_latency + ', page_speed=' + page_speed +
            ', corejs_speed=' + corejs_speed + ', page_stay=' + page_stay + ', avg_req_time=' + _st.avg_req_time + ', timestamp_out=' + timestamp_out)
    }

    // udpate stats
    var use_beacon = true
    if (use_beacon && navigator.sendBeacon) {
        var keys = Object.keys(data)
        var fd = new FormData()
        for (var i = 0, max = keys.length; i < max; i++) {
            fd.append(keys[i], data[keys[i]])
        }
        navigator.sendBeacon(botrx_ajax_obj.ajax_url, fd)

    } else {
        jQuery.ajax({
            type: "POST",
            url: botrx_ajax_obj.ajax_url,
            data: data,
            error: function (jqXHR, status, err) {
                console.error('[botrx_stats_update]', status, err)
            }
        })
    }

    function get_response_end() {
        var botrx_performance = window.performance || window.mozPerformance || window.msPerformance || window.webkitPerformance || {}
        if ("undefined" == typeof botrx_performance.timing) {
            return 0
        }
        return botrx_performance.timing.responseEnd
    }

    function get_server_latency() {
        var botrx_performance = window.performance || window.mozPerformance || window.msPerformance || window.webkitPerformance || {}
        if ("undefined" == typeof botrx_performance.timing) {
            return 0
        }
        var val = botrx_performance.timing.responseEnd - botrx_performance.timing.connectEnd
        return val > 0 ? val : 0
    }

    function get_page_speed() {
        var botrx_performance = window.performance || window.mozPerformance || window.msPerformance || window.webkitPerformance || {}
        if ("undefined" == typeof botrx_performance.timing) {
            return 0
        }
        var val = botrx_performance.timing.loadEventEnd - botrx_performance.timing.responseEnd
        return val > 0 ? val : 0
    }

}

function botrx_addEventListener(element, eventName, listener) {
    if (element.addEventListener) {
        element.addEventListener(eventName, listener);
    } else {
        element.attachEvent('on' + eventName, listener);
    }
}


function botrx_polyfill() {
    if (typeof Object.assign != 'function') {
        Object.assign = function (target, varArgs) { // .length of function is 2
            'use strict';
            if (target == null) { // TypeError if undefined or null
                throw new TypeError('Cannot convert undefined or null to object');
            }

            var to = Object(target);

            for (var index = 1; index < arguments.length; index++) {
                var nextSource = arguments[index];

                if (nextSource != null) { // Skip over if undefined or null
                    for (var nextKey in nextSource) {
                        // Avoid bugs when hasOwnProperty is shadowed
                        if (Object.prototype.hasOwnProperty.call(nextSource, nextKey)) {
                            to[nextKey] = nextSource[nextKey];
                        }
                    }
                }
            }
            return to;
        };
    }
}