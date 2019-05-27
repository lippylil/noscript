let include = importScript;
include("/lib/log.js");
include("/xss/InjectionChecker.js");
onmessage = async e => {
  let xssReq = e.data;
  let {destUrl} = xssReq;
  let ic = new (await this.InjectionChecker)();
  let {timing} = ic;
  timingsMap.set(request.id, timing);
  timing.fatalTimeout = true;

  let postInjection = xssReq.isPost &&
      request.requestBody && request.requestBody.formData &&
      await ic.checkPost(request.requestBody.formData, skipParams);

  if (timing.tooLong) {
    log("[XSS] Long check (%s ms) - %s", timing.elapsed, JSON.stringify(xssReq));
  }

  let protectName = ic.nameAssignment;
  let urlInjection = await ic.checkUrl(destUrl, skipRx);
  protectName = protectName || ic.nameAssignment;

  return !(protectName || postInjection || urlInjection) ? null
    : { protectName, postInjection, urlInjection };
}
