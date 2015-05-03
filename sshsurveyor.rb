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

        # Start loggers for app. Dump to stdout only in debug mode
        @self_logs = SelfLogs.new(Logger.new(self_log_file), nil)
        @self_logs.stdout = Logger.new(STDOUT) if @cfg['run_mode'] == 'full_debug'

        trace("Started surveying #{@auth_log.file}")

        # refused is a hash of ip address and the count of offenses from this ip
        # when it reaches the maximum threshold (3) the ip is added to the banned
        # addresses and removed from the hash
        @refused = {}

        # If state file exists, reload the until now refused ips avoiding to reparse the file
        # Otherwise the auth log will be parsed with the risk of missing some intrusion cases
        # if log has rotated inbetween
        if File.exists?(state_file)
            @refused = Psych.load(IO.read(state_file))
            @auth_log.size = @refused.delete('size')
            trace("Previous state reloaded:")
            @refused.each { |k, v| trace("  IP #{k}: #{v} attempt(s)") }
        end

        # banned is initialized with the entries in hosts.deny and grows each time
        # a refused ip reaches the maximum
        @banned = []
        IO.foreach(hosts_deny) { |line| @banned << line.split('sshd:')[1].strip if line.match(/^sshd:/) }

        # Cleanup refused if any duplicates between banned and refused
        @banned.each { |ip| @refused.delete_if { |k, v| k.start_with?(ip) } }

        # Keep track of allowed hosts, don't want to ban regular user cause (s)he messed the password...
        @allowed = []
        IO.foreach('/etc/hosts.allow') { |line| @allowed << line.split('sshd:')[1].strip if line.match(/^sshd:/) }

        @block = BlockStruct.new(0, [])
    end

    # Writes a message to script logs
    def trace(msg)
        @self_logs.file.info(msg)
        @self_logs.stdout.info(msg) if @self_logs.stdout
    end

    # Returns the system auth log to parse
    # Returns a local file name if in debug mode
    def auth_log
        return './auth.log' if @cfg['run_mode'] == 'full_debug'

        AUTH_LOG_FILES.map { |log_file| return log_file if File.exists?(log_file) }

        return nil
    end

    # Returns hosts.deny file name depending on the debug mode
    def hosts_deny
        return @cfg['run_mode'] == 'full_debug' ? './hosts.deny' : '/etc/hosts.deny'
    end

    # Returns script log file
    def self_log_file
        return File.join(File.dirname(__FILE__), 'sshsurveyor.log')
    end

    # Returns state file name
    def state_file
        return File.join(File.dirname(__FILE__), 'state.json')
    end

    # Saves the current refused ips to a json file
    # Adds a 'size' entry to save the file size at the time the script was stopped
    def save_state
        @refused['size'] = @auth_log.size
        IO.write(state_file, Psych.to_json(@refused))
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
        return @cfg['ban_prefix_size'] == 4 ? ip : ip.split('.')[0..@cfg['ban_prefix_size']-1].join('.')+'.'
    end

    def production_mode?
        return @cfg['run_mode'] == 'prod'
    end

    def analyze_block
        unless production_mode?
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

        # We were on a block that's not a threat
        if ips.empty?
            trace("No matching regex in block, exiting") unless production_mode?
            @block.lines.clear
            return
        end

        # In a standard case there should be only the same ip in the block
        ips = ips.uniq
        trace("Warning: more than 1 IP found in the same block!") if ips.size > 1

        # Parse each ip (normally only one)
        ips.map do |ip|
            # Skip if someone is doing stupid things on allowed host or already banned
            if @allowed.detect { |allowed| ip.start_with?(allowed) }
                trace("Warning: allowed IP #{ip} failed to authenticate (block [#{@block.pid}])")
                next
            end
            if @banned.detect { |banned| ip.start_with?(banned) }
                trace("IP #{ip} is already banned, skipping analysis") unless production_mode?
                next
            end

            trace("Detected login attempt from #{ip} (block [#{@block.pid}])")

            # Increment the offenses count
            @refused[ip] ? @refused[ip] += count : @refused[ip] = count
            trace("Updating refused[#{ip}], count is now #{@refused[ip]}")

            # If over 3 times, the ip is added to hosts.deny, saved in banned and removed from refused
            if @refused[ip] >= @cfg['max_attempts']
                trace("Adding #{ip} to banned -> deny #{ip_to_ban_size(ip)}")
                File.open(hosts_deny, 'a') { |file| file.write("sshd: #{ip_to_ban_size(ip)}\n") }
                @banned << ip_to_ban_size(ip)
                @refused.delete(ip)
                send_mail(ip) if @cfg['mail']['active']
            end
        end

        @block.lines.clear
    end

    # Add a line to current block if it has the same pid or start
    # a new block if it's different
    def build_block(line)
        if line.match(/refused connect/)
            trace(line)
        else
            line.match(/sshd\[([0-9]+)\]: /) do |m|
                pid = m.captures.first.to_i
                unless pid == @block.pid
                    analyze_block unless @block.lines.empty?
                    @block.pid = pid
                end
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

    # Starts the analyze process from the missing piece of the file or the whole file
    # if the file is smaller, probably due to log rotation.
    def check_log_file
        size = File.size(@auth_log.file)
        size > @auth_log.size ? parse_chunk(size-@auth_log.size) : parse_file
        analyze_block unless @block.lines.empty?
        @auth_log.size = size
    end

    # Repeatedly check if the log file changed in size
    # If size has changed, it will trigger the log analysis
    def main_loop
        %w[INT TERM].map { |sig| Signal.trap(sig) { save_state; exit(0) } }

        while true
            check_log_file unless File.size(@auth_log.file) == @auth_log.size
            sleep(@cfg['check_interval'])
        end
    end
end

SSHSurveyor.new.main_loop
