# ids_middleware_v2.rb

require 'cgi'
require 'json'
require 'time'
require 'securerandom'

class RealTimeIDS
  BLOCK_THRESHOLD = 5
  BAN_DURATION = 600

  MODES = [:enforce, :advisory]

  @@banned_ips = {}
  @@recommendations = []

  MALICIOUS_PATTERNS = {
    sql_injection: { regex: /(\bUNION\b|\bSELECT\b|\bDROP\b|\bOR\b.+\=.+)/i, score: 3 },
    xss: { regex: /(<script>|javascript:|onerror=|onload=)/i, score: 3 },
    command_injection: { regex: /(\||&&|;|\$\(|`)/, score: 4 },
    path_traversal: { regex: /(\.\.\/|\.\.\\)/, score: 2 },
    encoding_abuse: { regex: /(%[0-9A-Fa-f]{2}){3,}/, score: 2 }
  }

  def initialize(app, mode: :advisory)
    raise "Invalid mode" unless MODES.include?(mode)

    @app = app
    @mode = mode
  end

  def call(env)
    req = Rack::Request.new(env)
    ip = req.ip

    if enforce_mode? && banned?(ip)
      return blocked_response("IP banned")
    end

    score, findings = analyze_headers(env)

    if score >= BLOCK_THRESHOLD
      handle_high_risk(ip, score, findings, req)
    elsif score > 0
      alert(ip, score, findings, req)
    end

    @app.call(env)
  end

  private

  def enforce_mode?
    @mode == :enforce
  end

  def advisory_mode?
    @mode == :advisory
  end

  def handle_high_risk(ip, score, findings, req)
    recommendation = build_recommendation(ip, score, findings, req)

    store_recommendation(recommendation)
    alert(ip, score, findings, req, recommendation)

    if enforce_mode?
      ban_ip(ip)
      return blocked_response("Blocked by IDS")
    end
  end

  def build_recommendation(ip, score, findings, req)
    {
      id: SecureRandom.uuid,
      timestamp: Time.now.iso8601,
      ip: ip,
      method: req.request_method,
      path: req.path,
      score: score,
      findings: findings,
      suggested_action: "BAN",
      confidence: confidence_level(score),
      expires_at: (Time.now + BAN_DURATION).iso8601
    }
  end

  def confidence_level(score)
    case score
    when 0..3 then "low"
    when 4..6 then "medium"
    else "high"
    end
  end

  def store_recommendation(rec)
    @@recommendations << rec

    # Optional: persist to file
    File.open("ids_recommendations.log", "a") do |f|
      f.puts(rec.to_json)
    end
  end

  def analyze_headers(env)
    score = 0
    findings = []

    env.each do |key, value|
      next unless key.start_with?("HTTP_")

      decoded = decode(value.to_s)

      MALICIOUS_PATTERNS.each do |type, rule|
        if decoded.match?(rule[:regex])
          score += rule[:score]
          findings << { header: key, type: type, value: value }
        end
      end

      if value.to_s.length > 500
        score += 2
        findings << { header: key, type: :abnormal_length }
      end
    end

    [score, findings]
  end

  def decode(value)
    CGI.unescape(value) rescue value
  end

  def banned?(ip)
    return false unless @@banned_ips[ip]

    if Time.now > @@banned_ips[ip]
      @@banned_ips.delete(ip)
      return false
    end

    true
  end

  def ban_ip(ip)
    @@banned_ips[ip] = Time.now + BAN_DURATION
  end

  def alert(ip, score, findings, req, recommendation=nil)
    log = {
      timestamp: Time.now.iso8601,
      ip: ip,
      method: req.request_method,
      path: req.path,
      score: score,
      findings: findings,
      recommendation_id: recommendation&.dig(:id),
      mode: @mode
    }

    puts "[IDS ALERT] #{log.to_json}"
  end

  def blocked_response(reason)
    [
      403,
      { "Content-Type" => "application/json" },
      [{ error: "Forbidden", reason: reason }.to_json]
    ]
  end

  # PUBLIC: expose recommendations for review
  def self.recommendations
    @@recommendations
  end
end
