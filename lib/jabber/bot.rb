#--
# Copyright (c) 2011 Brett Stimmerman <brettstimmerman@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#   * Neither the name of this project nor the names of its contributors may be
#     used to endorse or promote products derived from this software without
#     specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#++

require 'rubygems'
require 'xmpp4r-simple'

module Jabber

  class Bot
    class Authorizee
      # ----------------------------------------------------------------- allowed?
      def allowed?( email )
        false
      end
      def self.domain( domain )
        DomainAuthorizee.new( domain )
      end
    end
    class DomainAuthorizee < Authorizee
      attr_reader :domain
      def initialize( domain )
        @domain = domain
      end
      # ----------------------------------------------------------------- allowed?
      def allowed?( email )
        email =~ /@#{domain}/
      end
    end
    class EmailAuthorizee < Authorizee
      def initialize( e )
        @email = 2
      end
            # ----------------------------------------------------------------- allowed?
      def allowed?( email )
        @email == email
      end
    end


    # Direct access to the underlying Jabber::Simple object.
    attr_reader :jabber

    # Creates a new Jabber::Bot object with the specified +config+ Hash, which
    # must contain +jabber_id+, +password+, and +master+ at a minimum.
    #
    # You may optionally give your bot a custom +name+. If +name+ is omitted,
    # the username portion of +jabber_id+ is used instead.
    #
    # You may choose to restrict a Jabber::Bot to listen only to its master(s),
    # or make it +public+.
    #
    # You may optionally specify a Jabber +presence+, +status+, and +priority+.
    # If omitted, they each default to +nil+.
    #
    # By default, a Jabber::Bot has only a single command, 'help [<command>]',
    # which displays a help message for the specified command, or all commands
    # if <command> is omitted.
    #
    # If you choose to make a public bot, only the commands you specify as
    # public, as well as the default 'help' command, will be public.
    #
    #   # A minimally confiugured private bot with a single master.
    #   bot = Jabber::Bot.new(
    #     :jabber_id => 'bot@example.com',
    #     :password  => 'secret',
    #     :master    => 'master@example.com'
    #   )
    #
    #   # A highly configured public bot with a custom name, mutliple masters,
    #   # Jabber presence, status, and priority.
    #   masters = ['master1@example.com', 'master2@example.com']
    #
    #   bot = Jabber::Bot.new(
    #     :name      => 'PublicBot',
    #     :jabber_id => 'bot@example.com',
    #     :password  => 'secret',
    #     :master    => masters,
    #     :is_public => true,
    #     :presence  => :chat,
    #     :priority  => 5,
    #     :status    => 'Hello, I am PublicBot.'
    #   )
    #
    def initialize(config)
      @config = config

      @config[:is_public] ||= false

      if @config[:name].nil? || @config[:name].length == 0
        @config[:name] = @config[:jabber_id].sub(/@.+$/, '')
      end
      master = @config.delete( :master )
      unless master.is_a?(Array)
        master = [master]
      end
      Command.set_master( master )

      @commands = { :spec => [], :meta => {} }

      # Default to asking about unknown commands.
      @config[:misunderstood_message] = @config[:misunderstood_message].nil? ? true : @config[:misunderstood_message]

      # Add the help command
      add_command(
        :syntax      => 'help [<command>]',
        :description => 'Display help for the given command, or all commands' +
            ' if no command is specified',
        :regex => /^help\s?(.+?)?$/,
        :alias => [ :syntax => '? [<command>]', :regex  => /^\?(\s+?.+?)?$/ ],
        :is_public => @config[:is_public]
      ) { |sender, message| help_message(sender, message) }
    end

    # Add a command to the bot's repertoire.
    #
    # Commands consist of a metadata Hash and a callback block. The metadata
    # Hash *must* contain the command +syntax+, a +description+ for display with
    # the builtin 'help' command, and a regular expression (+regex+) to detect
    # the presence of the command in an incoming message.
    #
    # The command parameter(s) will be parsed from group(s) (text between
    # parenthesis) in the +regex+. If there's none, one, or more than one
    # occurrence, the callback block will receive respectively nil, a String,
    # or an Array.
    # e.g. With a command defined like this: /^cmd\s+(.+)\s+(.+)\s+(.+)$/,
    # writing "cmd foo bar 42" will send ["foo", "bar", "42"] to the callback
    # block.
    #
    # The metadata Hash may optionally contain an array of command aliases. An
    # +alias+ consists of an alias +syntax+ and +regex+. Aliases allow the bot
    # to understand command shorthands. For example, the default 'help' command
    # has an alias '?'. Saying either 'help' or '?' will trigger the same
    # command callback block.
    #
    # The metadata Hash may optionally contain a +is_public+ flag, indicating
    # the bot should respond to *anyone* issuing the command, not just the bot
    # master(s). Public commands are only truly public if the bot itself has
    # been made public.
    #
    # The specified callback block will be triggered when the bot receives a
    # message that matches the given command regex (or an alias regex). The
    # callback block will have access to the sender and the parameter(s) (not
    # including the command itself), and should either return a String response
    # or +nil+. If a callback block returns a String response, the response will
    # be delivered to the Jabber id that issued the command.
    #
    # Examples:
    #
    #   # Say 'puts foo' or 'p foo' and 'foo' will be written to $stdout.
    #   # The bot will also respond with "'foo' written to $stdout."
    #   add_command(
    #     :syntax      => 'puts <string>',
    #     :description => 'Write something to $stdout',
    #     :regex       => /^puts\s+(.+)$/,
    #     :alias       => [ :syntax => 'p <string>', :regex => /^p\s+(.+)$/ ]
    #   ) do |sender, message|
    #     puts "#{sender} says #{message}."
    #     "'#{message}' written to $stdout."
    #   end
    #
    #   # 'puts!' is a non-responding version of 'puts', and has two aliases,
    #   # 'p!' and '!'
    #   add_command(
    #     :syntax      => 'puts! <string>',
    #     :description => 'Write something to $stdout (without response)',
    #     :regex       => /^puts!\s+(.+)$/,
    #     :alias       => [ 
    #       { :syntax => 'p! <string>', :regex => /^p!\s+(.+)$/ },
    #       { :syntax => '! <string>', :regex => /^!\s+(.+)$/ }
    #     ]
    #   ) do |sender, message|
    #     puts "#{sender} says #{message}."
    #     nil
    #   end
    #
    #  # 'rand' is a public command that produces a random number from 0 to 10
    #  add_command(
    #   :syntax      => 'rand',
    #   :description => 'Produce a random number from 0 to 10',
    #   :regex       => /^rand$/,
    #   :is_public   => true
    #  ) { rand(10).to_s }
    #
    def add_command(command, &callback)
      Command.new( command, &callback )
    end
    
    class Command
      attr_reader :syntax, :description, :is_public, :is_alias, :name
      def initialize( args, &callback )
        raise "Command missing name!" unless args[:syntax]
        @name = command_name( args[:syntax] )
        @syntax = args[:syntax].is_a?( Array ) ? args[:syntax] : [ args[:syntax] ]
        @description = args[:description]
        @authorizees = args[:authorizees]
        @authorizees = [@authorizees] unless @authorizees.is_a?( Array ) 

        @is_public = args[:is_public] || false
        @regex = args[:regex]
        @is_alias = false
        @callback = callback
        self.class.store_command( @name, self )
        if args[:alias]
          command[:alias].each do |a|
            add_command_alias( self, a, callback)
          end
        end
      end
      def self.set_master( master )
        @master = master
      end
      def run( message )
        match = message.match( regex )
        params = match.captures
        params = params.pop if params.count < 2
        response = callback.call( sender, params )
        deliver( sender, response ) unless response.nil?
      end
      def self.find_matching_command( message )
        @@commands.values.each do |command|
          message.match( command.regex )
          return command unless match.nil?
        end
        return nil
      end
      def self.master
        @master
      end
      def authorized?( sender )
        self.class.master.include?( sender )
      end
      def self.by_name
        @@commands.keys.sort.each do |command_name|
          yield @@commands[command_name]
      end
      def self.named( name )
        @@commands[name]
      end
      
      def show_in_help_for_sender( sender )
       !is_alias && ( is_public || authorized?( sender ) )
     end
          # Add a command alias for the given original +command_name+
      def add_command_alias( original, alias_command ) #:nodoc:
        original.syntax << alias_command[:syntax]
        alias_command[:is_public] = original_command.is_public
        alias = self.class.new( alias_command )
        alias.mark_as_alias!
      end


      def self.store_command( command )
        @@commands ||= { }
        @@commands[command.name] = command
      end
      def self.all
        @@commands
      end
      def help_description
        syntax.map { |syntax| "#{syntax}\n" }.join('') + "  #{command.description}\n\n"
      end
      def short_help_description
        help_description
      end
      protected
      
      def mark_as_alias!
        @is_alias = true
      end
      
      private

      def command_name(syntax) #:nodoc:
        syntax = syntax.trim
        if syntax =~ /\s/
          syntax.sub(/^(\S+).*/, '\1')
        else
          syntax
        end
      end
    end
    # Connect the bot, making it available to accept commands.
    # You can specify a custom startup message with the ':startup_message'
    # configuration setting.
    def connect
      @jabber = Jabber::Client.new( jabber_id )
      if @config[:host]
        @jabber.connect( @config[:host], 5222 )
      else
        @jabber.connect
      end
      @jabber.auth( @config[:password] )
      @jabber.send( Jabber::Presence.new.set_type( :available ) )
      deliver( Command.master, (@config[:startup_message] || "NAME reporting for duty.").gsub("NAME", @config[:name]))

      start_listener_thread
      Thread.stop
    end


    # Deliver a message to the specified recipient(s). Accepts a single
    # recipient or an Array of recipients.
    def deliver( to, message )
      to = [to] unless to.is_a?( Array )
      to.each do |email|
        msg = Jabber::Message::new( email, message )
        msg.type = :chat
        @jabber.send( msg )
      end
    end


    # Disconnect the bot.  Once the bot has been disconnected, there is no way
    # to restart it by issuing a command.
    def disconnect
      if @jabber.connected?
        deliver( Command.master, "#{@config[:name]} disconnecting...")
        @jabber.disconnect
      end
    end

    # Sets the bot presence, status message and priority.
    def presence(presence=nil, status=nil, priority=nil)
      @config[:presence] = presence
      @config[:status]   = status
      @config[:priority] = priority

      status_message = Presence.new(presence, status, priority)
      @jabber.send!(status_message) if @jabber.connected?
    end

    # Sets the bot presence. If you need to set more than just the presence,
    # use presence() instead.
    #
    # Available values for presence are:
    #
    #   * nil   : online
    #   * :chat : free for chat
    #   * :away : away from the computer
    #   * :dnd  : do not disturb
    #   * :xa   : extended away
    #
    def presence=(presence)
      presence(presence, @config[:status], @config[:priority])
    end

    # Set the bot priority. Priority is an integer from -127 to 127. If you need
    # to set more than just the priority, use presence() instead.
    def priority=(priority)
      presence(@config[:presence], @config[:status], priority)
    end

    # Set the status message. A status message is just a String, e.g. 'I am
    # here.' or 'Out to lunch.' If you need to set more than just the status
    # message, use presence() instead.
    def status=(status)
      presence(@config[:presence], status, @config[:priority])
    end

    private

    # Returns the default help message describing the bot's command repertoire.
    # Commands are sorted alphabetically by name, and are displayed according
    # to the bot's and the commands's _public_ attribute.
    def help_message(sender, command_name) #:nodoc:
      if command_name.nil? || command_name.length == 0
        # Display help for all commands
        help_message = "I understand the following commands:\n\n"
        Command.by_name do |command|
          if command.show_in_help?
            help_message += command.short_help_description
          end
        end
      else
        # Display help for the given command
        command = Command.named( command_name )

        if command.nil? && command.show_in_help?
          help_message = "I don't understand '#{command_name}' Try saying" +
              " 'help' to see what commands I understand."
        else
          command.help_description
        end
      end

      help_message
    end

    # Parses the given command message for the presence of a known command by
    # testing it against each known command's regex. If a known command is
    # found, the command parameters are parsed from groups defined in the
    # regex, if any. They are passed on to the callback block this way:
    # +nil+ if there's no parameter, a String if there's just one occurrence,
    # or an Array if there's more than one occurence.
    # 
    # If the callback returns a non- +nil+ value, it will be delivered to the
    # sender.
    #
    # If an unkown command is found, the bot will default to displaying the
    # help message. You can disable this by setting +:misunderstood_message+
    # to false in the bot configuration.
    #
    # If the bot has not been made public, commands from anyone other than the
    # bot master(s) will be silently ignored.
    def parse_command( sender, message) #:nodoc:
      message.strip!
      command = Command.find_matching_command( message )
      if command && command.authorized?( sender )
        command.run( message, sender )
      else
        if @config[:misunderstood_message]
          response = "I don't understand '#{message.strip}' Try saying 'help' " +
              "to see what commands I understand."
          deliver(sender, response)
        end
      end
    end
    def jabber_id
      @jabber_id ||= Jabber::JID::new( @config[:jabber_id] )
    end


    # Creates a new Thread dedicated to listening for incoming chat messages.
    # When a chat message is received, the bot checks if the sender is its
    # master. If so, it is tested for the presence commands, and processed
    # accordingly. If the bot itself or the command issued is not made public,
    # a message sent by anyone other than the bot's master is silently ignored.
    #
    # Only the chat message type is supported. Other message types such as
    # error and groupchat are not supported.
    def start_listener_thread
      @jabber.add_message_callback do |m|
        message = m.body
        if message && message != '' && !m.composing?
          parse_command( m.from, message )
        end
      end
    end


  end
end
