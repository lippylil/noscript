let include = src => {
  if (Array.isArray(src)) importScripts(...src);
  else importScripts(src);
}

let XSS = {};
include("/lib/log.js");

for (let logType of ["log", "debug", "error"]) {
  this[logType] = (...log) => {
    postMessage({log, logType});
  }
}

include("InjectionChecker.js");
Entities = {
  convertAll(s) { return s },
};

{
  let timingsMap = new Map();

  let Handlers = {
    async check({xssReq, skip}) {
      let {destUrl, unparsedRequest: request} = xssReq;
      let {
        skipParams,
        skipRx
      } = skip;

      let ic = new (await XSS.InjectionChecker)();
      log("Hello from ICW", Date.now() - xssReq.timestamp);
      let {timing} = ic;
      timingsMap.set(request.requestId, timing);
      timing.fatalTimeout = true;

      let postInjection = xssReq.isPost &&
          request.requestBody && request.requestBody.formData &&
          await ic.checkPost(request.requestBody.formData, skipParams);
      log("ICW2")
      if (timing.tooLong) {
        log("[XSS] Long check (%s ms) - %s", timing.elapsed, JSON.stringify(xssReq));
      }

      let protectName = ic.nameAssignment;
      let urlInjection = await ic.checkUrl(destUrl, skipRx);
      protectName = protectName || ic.nameAssignment;
      log("ICW3");
      postMessage(!(protectName || postInjection || urlInjection) ? null
        : { protectName, postInjection, urlInjection }
      );
    },

    requestDone({requestId}) {
      let timing = timingsMap.get(requestId);
      if (timing) {
        timing.interrupted = true;
        timingsMap.delete(requestId);
      }
    }
  }

  onmessage = async e => {
    let msg = e.data;
    if (msg.handler in Handlers) try {
      await Handlers[msg.handler](msg);
    } catch (e) {
      postMessage({error: e});
    }
  }

}
