WITH logs AS (
 SELECT path,status_code,request_json::jsonb q,
 CASE WHEN position(chr(92)||'u0000' in response_json)=0 THEN response_json::jsonb ELSE '{}'::jsonb END r
 FROM api_request_logs WHERE created_at >= '2026-09-18T02:30:00.000Z' AND created_at < '2026-10-18T02:30:00.000Z' AND path IN ('/v1/whois','/v2/whois','/v1/whois/bulk')
), inputs AS (
 SELECT CASE WHEN jsonb_typeof(q#>'{query,domain}')='array' THEN q#>>'{query,domain,0}' ELSE q#>>'{query,domain}' END domain,status_code,r
 FROM logs WHERE path <> '/v1/whois/bulk'
 UNION ALL
 SELECT d.domain,status_code,NULL::jsonb FROM logs CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(q#>'{body,domains}')='array' THEN q#>'{body,domains}' ELSE '[]'::jsonb END) d(domain) WHERE path='/v1/whois/bulk'
)
SELECT json_build_object('domain',domain,'requests',count(*),'positive',count(*) FILTER(WHERE r->>'registered'='true' AND r#>>'{edge_summary,authoritative_source}' IN ('rdap','whois','cache')))
FROM inputs GROUP BY domain ORDER BY count(*) DESC;
