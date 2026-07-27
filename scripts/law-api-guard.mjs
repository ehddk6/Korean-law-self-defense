export function assertOfficialApiSuccess(payload, context) {
  const text = String(payload || "");
  const xmlCode = text.match(/<resultCode[^>]*>\s*(?:<!\[CDATA\[)?([^<\]]+)(?:\]\]>)?\s*<\/resultCode>/i)?.[1]?.trim();
  const xmlMessage = text.match(/<resultMsg[^>]*>\s*(?:<!\[CDATA\[)?([^<\]]+)(?:\]\]>)?\s*<\/resultMsg>/i)?.[1]?.trim();
  let jsonCode;
  let jsonMessage;
  if (!xmlCode && text.trimStart().startsWith("{")) {
    try {
      const queue = [JSON.parse(text)];
      while (queue.length > 0) {
        const item = queue.shift();
        if (!item || typeof item !== "object") continue;
        if (item.resultCode !== undefined) jsonCode = String(item.resultCode).trim();
        if (item.resultMsg !== undefined) jsonMessage = String(item.resultMsg).trim();
        if (jsonCode) break;
        queue.push(...Object.values(item).filter((value) => value && typeof value === "object"));
      }
    } catch {
      // 상세 파서는 호출 지점에서 원래의 JSON/XML 오류로 처리한다.
    }
  }
  const code = xmlCode || jsonCode;
  const message = xmlMessage || jsonMessage || "";
  const successCodes = new Set(["0", "00", "success", "ok"]);
  if ((code && !successCodes.has(code.toLowerCase())) || /^fail(?:ure)?$/i.test(message)) {
    throw new Error(`${context}: 법제처 API가 실패 응답을 반환했습니다${code ? ` (resultCode=${code})` : ""}. 인증키·서비스 승인 상태를 확인하세요.`);
  }
}

export function guardOfficialApiResponses(client) {
  const searchLaw = client.searchLaw.bind(client);
  client.searchLaw = async (...args) => {
    const response = await searchLaw(...args);
    assertOfficialApiSuccess(response, "법령 검색 실패");
    return response;
  };
  const fetchApi = client.fetchApi.bind(client);
  client.fetchApi = async (...args) => {
    const response = await fetchApi(...args);
    assertOfficialApiSuccess(response, "공식 법률자료 조회 실패");
    return response;
  };
  const getLawText = client.getLawText.bind(client);
  client.getLawText = async (...args) => {
    const response = await getLawText(...args);
    assertOfficialApiSuccess(response, "법령 원문 조회 실패");
    return response;
  };
}

export function sanitizePrecedentSearchResult(result) {
  return {
    ...result,
    hits: (result.hits || []).map((hit) => ({
      ...hit,
      link: `https://www.law.go.kr/LSW/precInfoP.do?precSeq=${encodeURIComponent(String(hit.id || ""))}`,
    })),
  };
}
