export function sanitizeMcpString(value, secret) {
  let result = String(value);
  // 법제처가 상세 링크에 OC를 되돌려 주는 경우 쿼리 전체를 제거한다.
  result = result.replace(/([?&])OC=[^&\s<>"']*(?:&amp;|&)?/gi, (match, separator) => {
    const hasFollowingParameter = /(?:&amp;|&)$/.test(match);
    return hasFollowingParameter ? separator : "";
  });
  for (const candidate of [secret, secret ? encodeURIComponent(secret) : ""]) {
    if (candidate) result = result.split(candidate).join("[REDACTED]");
  }
  return result;
}

export function sanitizeMcpValue(value, secret) {
  if (typeof value === "string") return sanitizeMcpString(value, secret);
  if (Array.isArray(value)) return value.map((item) => sanitizeMcpValue(item, secret));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, sanitizeMcpValue(item, secret)]));
  }
  return value;
}

export function sanitizeMcpLine(line, secret) {
  try {
    return JSON.stringify(sanitizeMcpValue(JSON.parse(line), secret));
  } catch {
    return sanitizeMcpString(line, secret);
  }
}
