COPY (
WITH r AS (SELECT regexp_replace(lower(request_json::jsonb#>>'{query,domain}'),'^.*\.','') tld,response_json::jsonb j FROM api_request_logs WHERE created_at >= '2026-09-18T02:30:00.000Z' AND created_at < '2026-10-18T02:30:00.000Z' AND path IN ('/v1/whois','/v2/whois') AND status_code=200 AND position(chr(92)||'u0000' in response_json)=0)
SELECT tld,j#>>'{edge_summary,authoritative_source}' source,j->>'registered' registered,j->>'available' available,count(*) requests FROM r GROUP BY 1,2,3,4 ORDER BY 1,2,3,4
) TO STDOUT WITH CSV HEADER;
