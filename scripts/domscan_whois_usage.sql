-- Read-only aggregate of DomScan's 30-day API request log. Run against the
-- production domscan PostgreSQL database; output contains suffixes and counts
-- only, never customer domains or raw WHOIS response text.
COPY (
  WITH calls AS (
    SELECT lower(request_json::jsonb #>> '{query,domain}') AS domain,
           status_code, response_json
      FROM api_request_logs
     WHERE path IN ('/v1/whois', '/v2/whois')
       AND created_at >= '2026-08-29'
       AND created_at < '2026-09-29'
    UNION ALL
    SELECT lower(domains.domain), logs.status_code, NULL::text
      FROM api_request_logs AS logs
      CROSS JOIN LATERAL jsonb_array_elements_text(logs.request_json::jsonb #> '{body,domains}') AS domains(domain)
     WHERE logs.path = '/v1/whois/bulk'
       AND logs.created_at >= '2026-08-29'
       AND logs.created_at < '2026-09-29'
  ), valid_calls AS (
    SELECT regexp_replace(domain, '^.*\.', '') AS tld,
           status_code, response_json
      FROM calls
     WHERE domain ~ '^[a-z0-9-]+(\.[a-z0-9-]+)+$'
  )
  SELECT tld,
         count(*) AS requests,
         count(*) FILTER (WHERE status_code = 200) AS http_200,
         count(*) FILTER (WHERE position('"relay_whois_used":true' in response_json) > 0) AS traditional_whois_used
    FROM valid_calls
   GROUP BY tld
   ORDER BY requests DESC, tld
) TO STDOUT WITH CSV HEADER;
