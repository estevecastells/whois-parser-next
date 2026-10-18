# Process retained sensitive text on its production host; output aggregates only.
require 'json'
require 'csv'
require 'open3'
require 'timeout'
require 'whois-parser'
query = <<~SQL
 SELECT json_build_object('domain',lower(request_json::jsonb#>>'{query,domain}'),'raw',response_json::jsonb->>'raw_whois','registered',response_json::jsonb->>'registered','available',response_json::jsonb->>'available')
 FROM api_request_logs WHERE created_at >= '2026-09-18T02:30:00.000Z' AND created_at < '2026-10-18T02:30:00.000Z' AND path IN ('/v1/whois','/v2/whois') AND status_code=200 AND position(chr(92)||'u0000' in response_json)=0 AND response_json::jsonb->>'raw_whois' IS NOT NULL;
SQL
hosts={'africa'=>'whois.nic.africa','biz'=>'whois.nic.biz','click'=>'whois.registry.click','dk'=>'whois.punktum.dk','gift'=>'whois.registry.gift','help'=>'whois.nic.help','homes'=>'whois.nic.homes','ie'=>'whois.weare.ie','io'=>'whois.nic.io','mu'=>'whois.tld.mu','open'=>'whois.nic.open','org'=>'whois.publicinterestregistry.org','pk'=>'whois.pknic.net.pk','ge'=>'whois.nic.ge','sr'=>'whois.sr','to'=>'whois.tonicregistry.to','uk'=>'whois.nic.uk'}
counts=Hash.new(0)
Open3.popen3('sudo','-u','postgres','psql','-d','domscan','-qAt','-c',query) do |input,output,errors,wait|
 input.close
 output.each_line do |line|
  begin
   row=JSON.parse(line); domain=row.fetch('domain'); tld=domain.split('.').last; raw=row.fetch('raw')
   expected=row['available']=='true' ? 'available' : row['registered']=='true' ? 'registered' : 'unknown'
   host=hosts[tld] || Whois::Server.find_for_domain(domain)&.host
   parser=Whois::Parser.parser_klass(host).new(Whois::Record::Part.new(body:raw,host:host))
   actual=Timeout.timeout(0.2) { parser.registered? ? 'registered' : parser.available? ? 'available' : 'unknown' }
   counts[[tld,expected,actual,raw.length>=2048 ? 'possibly_truncated' : 'retained']] += 1
  rescue StandardError, LoadError => e
   counts[[tld||'unknown',expected||'unknown',"error:#{e.class}",raw && raw.length>=2048 ? 'possibly_truncated' : 'retained']] += 1
  end
 end
 abort 'production query failed' unless wait.value.success?
end
puts %w[tld recorded_class parser_class preview_state count].to_csv
counts.sort.each{|k,v| puts [*k,v].to_csv}
