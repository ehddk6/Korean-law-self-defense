#!/usr/bin/env node

import { LawApiClient } from "../node_modules/korean-law-mcp/build/lib/api-client.js";
import { searchPrecedentsStructured } from "../node_modules/korean-law-mcp/build/tools/precedent-search-core.js";
import { findLaws } from "../node_modules/korean-law-mcp/build/lib/law-search.js";
import { guardOfficialApiResponses, sanitizePrecedentSearchResult } from "./law-api-guard.mjs";
import { sanitizeMcpString, sanitizeMcpValue } from "./mcp-output-sanitizer.mjs";

// 법제처가 응답 본문·링크에 OC를 되돌려 주는 경우에 대비해
// 모든 표준 출력·오류 메시지는 새니타이저를 거쳐 내보낸다.
const OUTPUT_SECRET = process.env.LAW_OC || "";

function fail(message) {
  process.stderr.write(`${sanitizeMcpString(message, OUTPUT_SECRET)}\n`);
  process.exitCode = 2;
}

function emit(payload) {
  process.stdout.write(`${JSON.stringify(sanitizeMcpValue(payload, OUTPUT_SECRET))}\n`);
}

function requireLawOc() {
  const value = process.env.LAW_OC || "";
  if (!value) {
    throw new Error("LAW_OC 사용자 환경변수가 필요합니다.");
  }
  return value;
}

async function readInput() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString("utf8").trim();
  return text ? JSON.parse(text) : {};
}

function cleanPrecedentDetail(data, requestedId) {
  const item = data?.PrecService;
  if (!item || typeof item !== "object") {
    throw new Error(`공식 판례 원문을 찾지 못했습니다: ${requestedId}`);
  }
  return {
    id: String(requestedId),
    title: item["사건명"] || "",
    case_number: item["사건번호"] || "",
    court: item["법원명"] || "",
    decision_date: item["선고일자"] || "",
    case_type: item["사건종류명"] || "",
    decision_type: item["판결유형"] || "",
    issues: item["판시사항"] || "",
    holding_summary: item["판결요지"] || "",
    referenced_laws: item["참조조문"] || "",
    referenced_precedents: item["참조판례"] || "",
    full_text: item["판례내용"] || "",
    source_url: `https://www.law.go.kr/LSW/precInfoP.do?precSeq=${encodeURIComponent(requestedId)}`,
  };
}

async function main() {
  const command = process.argv[2];
  const input = await readInput();
  const client = new LawApiClient({ apiKey: requireLawOc() });
  guardOfficialApiResponses(client);
  if (command === "precedent-search") {
    const result = await searchPrecedentsStructured(
      client,
      {
        query: String(input.query || ""),
        search: Number(input.search || 1),
        display: Math.min(Math.max(Number(input.display || 20), 1), 100),
        page: Math.max(Number(input.page || 1), 1),
        court: input.court || undefined,
        sort: input.sort || undefined,
        fromDate: input.from_date || undefined,
        toDate: input.to_date || undefined,
      },
      { fallbackPolicy: "none" },
    );
    emit(sanitizePrecedentSearchResult(result));
    return;
  }
  if (command === "precedent-detail") {
    const id = String(input.id || "").trim();
    if (!/^\d+$/.test(id)) throw new Error("판례일련번호는 숫자여야 합니다.");
    const response = await client.fetchApi({
      endpoint: "lawService.do",
      target: "prec",
      type: "JSON",
      extraParams: { ID: id },
    });
    emit(cleanPrecedentDetail(JSON.parse(response), id));
    return;
  }
  if (command === "law-search") {
    const query = String(input.query || "").trim();
    if (!query) throw new Error("법령 검색어가 필요합니다.");
    const laws = await findLaws(client, query, undefined, Number(input.max || 10), 100);
    emit({ laws });
    return;
  }
  if (command === "law-detail") {
    const mst = String(input.mst || "").trim();
    if (!/^\d+$/.test(mst)) throw new Error("법령일련번호(MST)는 숫자여야 합니다.");
    const response = await client.getLawText({ mst, jo: input.jo || undefined });
    emit({
      mst,
      source_url: `https://www.law.go.kr/법령/법령정보?lsiSeq=${encodeURIComponent(mst)}`,
      payload: JSON.parse(response),
    });
    return;
  }
  throw new Error("지원 명령: precedent-search, precedent-detail, law-search, law-detail");
}

main().catch((error) => {
  fail(error instanceof Error ? error.message : String(error));
});
