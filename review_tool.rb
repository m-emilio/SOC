# review_tool.rb

require './ids_middleware_v2'
require 'json'

recs = RealTimeIDS.recommendations

puts "=== IDS Recommendations ==="

recs.each do |r|
  puts "\nID: #{r[:id]}"
  puts "IP: #{r[:ip]}"
  puts "Score: #{r[:score]} (#{r[:confidence]})"
  puts "Path: #{r[:path]}"
  puts "Suggested: #{r[:suggested_action]}"
  puts "Expires: #{r[:expires_at]}"
  puts "Findings: #{r[:findings]}"
end
