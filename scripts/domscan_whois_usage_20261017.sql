COPY (
WITH logs AS (
 SELECT path,status_code,request_json::jsonb q,
 CASE WHEN position(chr(92)||'u0000' in response_json)=0 THEN response_json::jsonb END r
 FROM api_request_logs WHERE created_at >= '2026-09-18T02:30:00.000Z' AND created_at < '2026-10-18T02:30:00.000Z' AND path IN ('/v1/whois','/v2/whois','/v1/whois/bulk')
), items AS (
 SELECT lower(q#>>'{query,domain}') domain,status_code,r FROM logs WHERE path <> '/v1/whois/bulk'
 UNION ALL
 SELECT lower(d.domain),status_code,NULL::jsonb FROM logs CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN jsonb_typeof(q#>'{body,domains}')='array' THEN q#>'{body,domains}' ELSE '[]'::jsonb END) d(domain) WHERE path='/v1/whois/bulk'
) SELECT regexp_replace(domain,'^.*\.','') tld,count(*) requests,
 count(*) FILTER(WHERE status_code=200) http_200,
 count(*) FILTER(WHERE r#>>'{edge_summary,relay_whois_used}'='true') traditional_whois_used,
 count(*) FILTER(WHERE r->>'registered'='true' AND r#>>'{meta,data_source}' IS DISTINCT FROM 'dns' AND r#>>'{edge_summary,authoritative_source}' IS DISTINCT FROM 'unknown') registered,
 count(*) FILTER(WHERE r->>'available'='true') available,
 count(*) FILTER(WHERE status_code=200 AND r->>'registered' IS NULL) unknown_or_unretained,
 count(*) FILTER(WHERE r#>>'{meta,data_source}'='dns') dns_fallback,
 count(*) FILTER(WHERE status_code=400) invalid_input,
 count(*) FILTER(WHERE status_code IN (402,429)) admission_rejected,
 count(*) FILTER(WHERE status_code>=500) upstream_error
 FROM items WHERE domain ~ '^[a-z0-9-]+(\.[a-z0-9-]+)+$' GROUP BY 1 ORDER BY requests DESC,tld
) TO STDOUT WITH CSV HEADER;
