-- Stream bounded, privacy-sensitive response previews to the parser replay
-- process over stdin. Never save or publish this output.
WITH previews AS (
  SELECT regexp_replace(lower(request_json::jsonb #>> '{query,domain}'), '^.*\.', '') AS tld,
         response_json::jsonb AS response
    FROM api_request_logs
   WHERE path IN ('/v1/whois', '/v2/whois')
     AND status_code = 200
     AND position(chr(92) || 'u0000' in response_json) = 0
)
SELECT json_build_object(
         'tld', tld,
         'raw', response->>'raw_whois',
         'registered', response->>'registered',
         'available', response->>'available'
       )
  FROM previews
 WHERE tld IN ('mn', 'cl', 'eu')
   AND response->>'raw_whois' IS NOT NULL;
