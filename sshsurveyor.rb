#!/usr/local/bin/ruby

require 'logger'
require 'net/smtp'
require 'psych'
require 'fileutils'

class SSHSurveyor

    # Where to find the log depending on the system
    AUTH_LOG_FILES = ['/var/log/auth.log', '/var/log/secure']

    # Regex to detect threat in a line
    AUTH_LOG_REGEX = /User .+ from |Invalid user .+ from |Failed password for|Did not receive/

    # Extract the first ip address between to blanks on a line
    IP_REGEX = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/

    # Keeps track of the log file name and its size
    AuthLogStruct = Struct.new(:file, :size)

    # Structure of a block that has to be analyzed.
    # It contains the pid and consecutive lines for that pid
    BlockStruct = Struct.new(:pid, :lines)

    # Self logs struct
    SelfLogs = Struct.new(:file, :stdout)


    def initialize
        @cfg = Psych.load_file(File.join(ENV['HOME'], '.config/sshsurveyor/config.yml'))

        # Init and check existence of system auth log. Abort if not found, no sense to continue
        @auth_log = AuthLogStruct.new(auth_log, 0)
        raise('No auth/secure log file found. Aborting.') if @auth_log.file.nil?

        # Make a roll from the log file if it already exists avoiding the log file
        # to grow at each startup with the same messages
        FileUtils.mv(self_log_file, self_log_file+'.'+Time.now.to_s.gsub(/ /, '@')) if File.exists?(self_log_file)

        # Start loggers for app. Dump to stdout only in debug mode
        @self_logs = SelfLogs.new(Logger.new(self_log_file), nil)
        @self_logs.stdout = Logger.new(STDOUT) if @cfg['debug']

        trace("Started surveying #{@auth_log.file}")

        # refused is a hash of ip address and the count of offenses from this ip
        # when it reaches the maximum threshold (3) the ip is added to the banned
        # addresses and removed from the hash
        @refused = {}

        # banned is initialized with the entries in hosts.deny and grows each time
        # a refused ip reaches the maximum
        @banned = []
        IO.foreach(hosts_deny) { |line| @banned << line.split('sshd:')[1].strip if line.match(/^sshd:/) }

        # Keep track of allowed hosts, don't want to ban regular user cause (s)he messed the password...
        @allowed = []
        IO.foreach('/etc/hosts.allow') { |line| @allowed << line.split('sshd:')[1].strip if line.match(/^sshd:/) }

        @block = BlockStruct.new(0, [])

    end

    def trace(msg)
        @self_logs.file.info(msg)
        @self_logs.stdout.info(msg) if @self_logs.stdout
    end

    def auth_log
        return './auth.log' if @cfg['debug']

        AUTH_LOG_FILES.map { |log_file| return log_file if File.exists?(log_file) }

        return nil
    end

    def hosts_deny
        return @cfg['debug'] ? './hosts.deny' : '/etc/hosts.deny'
    end

    def self_log_file
        return File.join(File.dirname(__FILE__), 'sshsurveyor.log')
    end

    def send_mail(ip)
        msg = "Subject: Surveyor@home banned a new IP\n\n"
        msg << "Surveyor banned IP #{ip} as #{ip_to_ban_size(ip)} in hosts.deny\n"

        smtp = Net::SMTP.new(@cfg['mail']['server'], @cfg['mail']['port'])
        smtp.enable_starttls
        smtp.start('', @cfg['mail']['recipient'], @cfg['mail']['passwd'], :login) do
            smtp.send_message(msg, @cfg['mail']['sender'], @cfg['mail']['recipient'])
        end
    end

    # Returns the ip truncated of its ban_prefix_size lower bytes.
    def ip_to_ban_size(ip)
        return ip if @cfg['ban_prefix_size'] == 4
        s = ''
        ip.split('.')[0..@cfg['ban_prefix_size']-1].map { |b| s << b+'.' }
        return s
    end

    # Check if an ip is already banned or not
    def is_banned(ip)
        return @banned.detect { |banned| ip.match(banned) || ip_to_ban_size(ip).match(banned) }
    end

    # Check if an ip is in allowed hosts
    def is_allowed(ip)
        return @allowed.detect { |allowed| ip.match(allowed) || ip_to_ban_size(ip).match(allowed) }
    end

    def analyze_block
        if @cfg['debug']
            trace("Analyzing #{@block.lines.size} line(s) block for pid #{@block.pid}:")
            @block.lines.map { |line| trace("  #{line}") }
        end

        # Parse each line of the block with each regex detecting a threat
        # If a match is found, the ip address is added to an array
        # If a line contains a number of repeat the match count is incremented accordingly
        ips = []
        count = 1
        @block.lines.map do |line|
            # The if modifier is necessary because we sometime get a domain name rather than the ip
            line.match(AUTH_LOG_REGEX) { |match| ips << line.match(IP_REGEX)[0] if line.match(IP_REGEX) }

            # Check if we have a repeat count for the offense
            count += line.match(/message repeated/) ? line.match(/repeated ([0-9]+) /).captures.first.to_i : 0
        end

        # In a standard case there should be only the same ip in the block
        ips = ips.compact.uniq

        # We were on a block that's not a threat
        if ips.empty?
            @block.lines.clear
            return
        end

        trace("WARNING: more than 1 IP found in the same block!") if ips.size > 1

        # Parse each ip (normally only one)
        ips.map do |ip|
            # Skip if someone is doing stupid things on allowed host or already banned
            if is_allowed(ip)
                trace("Warning: allowed IP #{ip} failed to authenticate (block [#{@block.pid}])")
                next
            end
            next if is_banned(ip)

            trace("Extracted suspicious IP #{ip} (block [#{@block.pid}])")

            # Increment the offenses count
            @refused[ip] ? @refused[ip] += count : @refused[ip] = count
            trace("Adding #{ip} to refused table, count is now #{@refused[ip]}")

            # If over 3 times, the ip is added to hosts.deny, saved in banned and removed from refused
            if @refused[ip] > 2
                trace("Adding #{ip} to banned -> deny #{ip_to_ban_size(ip)}")
                File.open(hosts_deny, 'a') { |file| file.write("sshd: #{ip_to_ban_size(ip)}\n") }
                @banned << ip_to_ban_size(ip)
                @refused.delete_if { |k, v| k == ip }
                # if @auth_log.size is 0, it means first parsing of file at startup. Don't send mail in this case
                send_mail(ip) if @cfg['mail']['active'] && @auth_log.size > 0
            end
        end

        @block.lines.clear
    end

    # Add a line to current block if it has the same pid or start
    # a new block if it's different
    def build_block(line)
        return if line.match(/refused connect/)

        line.match(/sshd\[([0-9]+)\]: /) do |m|
            pid = m.captures.first.to_i
            if pid == @block.pid
                @block.lines << m.post_match
            else
                analyze_block unless @block.lines.empty?
                @block.pid = pid
                @block.lines << m.post_match
            end
        end
    end

    # Parse the chunk of file that changed from last check
    def parse_chunk(size)
        File.open(@auth_log.file, 'r') do |f|
            f.seek(-size, IO::SEEK_END)
            f.read(size).split("\n").each { |line| build_block(line) }
        end
    end

    # Parse the full file
    def parse_file
        IO.binread(@auth_log.file).split("\n").each { |line| build_block(line) }
    end

    # Check if the size of the log file changed. In this case it starts
    # the analyze process from the missing piece of the file or the whole file.
    def check_log_size
        return if File.size(@auth_log.file) == @auth_log.size

        size = File.size(@auth_log.file)
        size > @auth_log.size ? parse_chunk(size-@auth_log.size) : parse_file
        analyze_block unless @block.lines.empty?
        @auth_log.size = size
    end

    # Repeatedly check if the log file changed in size
    # If size changed, it will trigger the analyze of the log
    def main_loop
        Signal.trap("TERM") {
            # trace("Surveyor shutdown on TERM signal.")
            exit(0)
        }
        # Signal.trap("HUP") { trace("SIGHUP trapped and ignored.") }

        if @cfg['debug']
            check_log_size
        else
            while true
                check_log_size
                sleep(10)
            end
        end
    end
end

SSHSurveyor.new.main_loop
