# Module, welches AccesRules fuer Controller/Actions und
# Model-Object umsetzt.
#
# Die Regeln werden aus der Datei "config/acces_rules.rb" geladen
#
# Author: Bernd Ledig
#

require 'singleton'

module Tuersteher

  # Logger to log messages with timestamp and severity
  class TLogger < Logger
    @@logger = nil

    def format_message(severity, timestamp, progname, msg)
      "#{timestamp.to_formatted_s(:db)} #{severity} #{msg}\n"
    end

    def self.logger
      return @@logger if @@logger
      @@logger = self.new(File.join(Rails.root, 'log', 'tuersteher.log'), 3)
      @@logger.level = INFO if Rails.env != 'development'
      @@logger
    end

    def self.logger= logger
      @@logger = logger
    end
  end

  class AccessRulesStorage
    include Singleton

    attr_reader :path_rules, :model_rules
    attr_accessor :rules_config_file # to set own access_rules-path

    DEFAULT_RULES_CONFIG_FILE = File.join(Rails.root, 'config', 'access_rules.rb')

    def initialize
      @path_rules = []
      @model_rules = []
    end

    # Laden der AccesRules aus den Dateien
    #  config/access_rules.rb
    # In der development-Enviroment wird diese nach jeder Änderung
    # neu geladen, sonst nur einmal
    def load_access_rules
      return if @was_read && Rails.env!='development'
      read_rules
    end

    def read_rules
      config_file = @rules_config_file || DEFAULT_RULES_CONFIG_FILE
      rules_file = File.new config_file
      if @last_mtime.nil? || rules_file.mtime > @last_mtime
        @last_mtime = rules_file.mtime
        content = rules_file.read
        eval content
        Tuersteher::TLogger.logger.info "Tuersteher::AccessRulesStorage: #{@path_rules.size} path-rules and #{@model_rules.size} model-rules"
      end
      rules_file.close
      @was_read = true
    end

    # definiert HTTP-Pfad-basierende Zugriffsregel
    #
    # path:            :all fuer beliebig, sonst String mit der http-path beginnen muss,
    #                  wird als RegEX-Ausdruck ausgewertet
    # method:          http-Methode, es sind hier erlaubt :get, :put, :delete, :post, :all
    # accepted_roles:  Aufzaehlung der erfoderlichen Rolen (oder-Verknuepfung), es sind nur Symbole zulaessig
    #                  hier ist auch ein Array von Symbolen möglich
    def grant_path url_path, http_methode, *accepted_roles
      @path_rules << PathAccessRule.new(url_path, http_methode, *accepted_roles)
    end

    # definiert HTTP-Pfad-basierende Ablehnungsregel
    #
    # path:            :all fuer beliebig, sonst String mit der http-path beginnen muss,
    #                  wird als RegEX-Ausdruck ausgewertet
    # method:          http-Methode, es sind hier erlaubt :get, :put, :delete, :post, :all
    # accepted_roles:  Aufzaehlung der erfoderlichen Rolen (oder-Verknuepfung), es sind nur Symbole zulaessig
    #                  hier ist auch ein Array von Symbolen möglich
    def deny_path url_path, http_methode, *accepted_roles
      rule = PathAccessRule.new(url_path, http_methode, *accepted_roles)
      rule.deny = true
      @path_rules << rule
    end

    # definiert Model-basierende Zugriffsregel
    #
    # model_class:  Model-Klassenname oder :all fuer alle
    # access_type:  Zugriffsart (:create, :update, :destroy, :all o.A. selbst definierte Typen)
    # roles         Aufzählung der erforderliche Rolen (:all für ist egal),
    #               hier ist auch ein Array von Symbolen möglich
    # block         optionaler Block, wird mit model und user aufgerufen und muss true oder false liefern
    #               hier ein Beispiel mit Block:
    #               <code>
    #                 # Regel, in der sich jeder User selbst aendern darf
    #                 grant_model(User, :update, :all){|model,user| model.id==user.id}
    #               </code>
    #
    def grant_model model_class, access_type, *roles, &block
      @model_rules << ModelAccessRule.new(model_class, access_type, *roles, &block)
    end

  end



  # Module zum Include in Controllers
  # Dieser muss die folgenden Methoden bereitstellen:
  #
  #   current_user : akt. Login-User
  #   access_denied :  Methode aus dem authenticated_system, welche ein redirect zum login auslöst
  #
  # Der Loginuser muss fuer die hier benoetigte Funktionalitaet
  # die Methode:
  #   has_role?(*roles)  # roles is Array of Symbols
  # besitzen.
  #
  # Beispiel der Einbindung in den ApplicationController
  #   include Tuersteher::ControllerExtensions
  #   before_filter :check_access # methode is from Tuersteher::ControllerExtensions
  #
  module ControllerExtensions


    # Pruefen Zugriff fuer eine Web-action
    #
    # path        Pfad der Webresource (String oder Hash mit Options)
    # method      http-Methode (:get, :put, :delete, :post), default ist :get
    #
    def path_access?(path, method = :get)

      # ist path eine Hash (also der alte Stil mit :controller=> .., :action=>..)
      # dann diese in ein http-path wandeln
      path = url_for(path.merge(:only_path => true)) if path.instance_of?(Hash)

      AccessRulesStorage.instance.load_access_rules # das load cached automatisch
      rule = AccessRulesStorage.instance.path_rules.detect do |r|
        r.fired?(path, method, current_user)
      end
      if Tuersteher::TLogger.logger.debug?
        if rule.nil?
          s = 'denied'
        elsif rule.deny
          s = "denied with #{rule}"
        else
          s = "granted with #{rule}"
        end
        Tuersteher::TLogger.logger.debug("Tuersteher: path_access?(#{path}, #{method})  =>  #{s}")
      end
      rule!=nil && !rule.deny
    end

    # Pruefen Zugriff auf ein Model-Object
    #
    # model       das Model-Object
    # permission  das geforderte Zugriffsrecht (:create, :update, :destroy, :get)
    #
    # liefert true/false
    def model_access? model, permission
      raise "Wrong call! Use: model_access(model-instance-or-class, permission)" unless permission.is_a? Symbol
      return false unless model

      AccessRulesStorage.instance.load_access_rules # das load cached automatisch
      access = AccessRulesStorage.instance.model_rules.detect do |rule|
        rule.has_access? model, permission, current_user
      end
      if Tuersteher::TLogger.logger.debug?
        if model.instance_of?(Class)
          Tuersteher::TLogger.logger.debug("Tuersteher: model_access?(#{model}, #{permission}) =>  #{access ? access : 'denied'}")
        else
          Tuersteher::TLogger.logger.debug("Tuersteher: model_access?(#{model.class}(#{model.respond_to?(:id) ? model.id : model.object_id }), #{permission}) =>  #{access ? access : 'denied'}")
        end
      end
      access!=nil
    end

    def self.included(base)
      base.class_eval do
        # Methoden path_access? und model_access? auch als Helper fuer die Views bereitstellen
        helper_method :path_access?, :model_access?
      end
    end

    protected

    # Pruefen, ob Zugriff des current_user
    # fuer aktullen Request erlaubt ist
    def check_access
      unless path_access?(request.request_uri, request.method)
        msg = "Tuersteher#check_access: access denied for #{request.request_uri} :#{request.method}"
        Tuersteher::TLogger.logger.warn msg
        logger.warn msg  # log message also for Rails-Default logger
        access_denied  # Methode aus dem authenticated_system, welche ein redirect zum login auslöst
      end
    end

  end


  class PathAccessRule
    attr_reader :path, :method, :roles, :deny

    METHOD_NAMES = [:get, :edit, :put, :delete, :post, :all].freeze


    # Zugriffsregel
    #
    # path          :all fuer beliebig, sonst String mit der http-path beginnen muss
    # method        http-Methode, es sind hier erlaubt :get, :put, :delete, :post, :all
    # needed_roles  Aufzaehlung der erfoderlichen Rolen (oder-Verknuepfung), es sind nur Symbole zulaessig
    #
    def initialize(path, method, *needed_roles)
      raise "wrong path '#{path}'! Must be a String or :all ." unless path==:all or path.is_a?(String)
      raise "wrong method '#{method}'! Must be #{METHOD_NAMES.join(', ')} !" unless METHOD_NAMES.include?(method)
      raise "needed_roles expected!" if needed_roles.empty?
      @roles = needed_roles.flatten
      for r in @roles
        raise "wrong role '#{r}'! Must be a symbol " unless r.is_a?(Symbol)
      end
      @path = path
      if path != :all
        # path in regex ^#{path} wandeln ausser bei "/",
        # dies darf keine Regex mit ^/ werden,
        # da diese ja immer matchen wuerde
        if path == "/"
          @path = /^\/$/
        else
          @path = /^#{path}/
        end
      end
      @method = method
    end


    # pruefen, ob Zugriff fuer angegebenen
    # path / method fuer den current_user erlaubt ist
    #
    # user ist ein Object (meist der Loginuser),
    # welcher die Methode 'has_role?(*roles)' besitzen muss.
    # *roles ist dabei eine Array aus Symbolen
    #
    def fired?(path, method, user)
      user = nil if user==:false # manche Authenticate-System setzen den user auf :false
      if @path!=:all && !(@path =~ path)
        return false
      end

      if @method!=:all && @method != method
        return false
      end

      # ist jetzt role :all, dann prinzipiell Zugriff erlaubt
      return true if @roles.first == :all

      if user && user.has_role?(*@roles)
        return true
      end
      false
    end


    def to_s
      "PathAccesRule[#{@path}, #{@method}, #{@roles.join(' ')}#{@deny ? ' deny' : ''}]"
    end

  end



  class ModelAccessRule
    attr_reader :clazz, :access_type, :role, :block


    # erzeugt neue Object-Zugriffsregel
    #
    # clazz         Model-Klassenname oder :all fuer alle
    # access_type   Zugriffsart (:create, :update, :destroy, :all o.A. selbst definierte Typem)
    # roles         Aufzählung der erforderliche Rolen (:all für ist egal),
    #               hier ist auch ein Array von Symbolen möglich
    # block         optionaler Block, wird mit model und user aufgerufen und muss true oder false liefern
    #               hier ein Beispiel mit Block:
    #               <code>
    #                 # Regel, in der sich jeder User selbst aendern darf
    #                 ModelAccessRule.new(User, :update, :all){|model,user| model.id==user.id}
    #               </code>
    #
    def initialize(clazz, access_type, *roles, &block)
      raise "wrong clazz '#{clazz}'! Must be a Class or :all ." unless clazz==:all or clazz.is_a?(Class)
      raise "wrong access_type '#{ access_type}'! Must be a Symbol ." unless  access_type.is_a?(Symbol)
      @roles = roles.flatten
      for r in @roles
        raise "wrong role '#{r}'! Must be a symbol " unless r.is_a?(Symbol)
      end
      @clazz = clazz.instance_of?(Symbol) ? clazz : clazz.to_s
      @access_type =  access_type
      @block = block
    end

    # liefert true, wenn zugriff fuer das angegebene model mit
    # der Zugriffsart perm für das security_object hat
    #
    # model des zupruefende ModelObject
    # perm gewunschte Zugriffsart (Symbol :create, :update, :destroy)
    #
    # user ist ein User-Object (meist der Loginuser),
    # welcher die Methode 'has_role?(*roles)' besitzen muss.
    # *roles ist dabei eine Array aus Symbolen
    #
    #
    def has_access? model, perm, user
      user = nil if user==:false # manche Authenticate-System setzen den user auf :false
      m_class = model.instance_of?(Class) ? model : model.class
      if @clazz!=m_class.to_s && @clazz!=:all
        #Tuersteher::TLogger.logger.debug("#{to_s}.has_access? => false why #{@clazz}!=#{model.class.to_s} && #{@clazz}!=:all")
        return false
      end

      if @access_type!=:all && @access_type!=perm
        #Tuersteher::TLogger.logger.debug("#{to_s}.has_access? => false why #{@access_type}!=:all && #{@access_type}!=#{perm}")
        return false
      end

      if @roles.first!=:all && (user.nil? || !user.has_role?(*@roles))
        #Tuersteher::TLogger.logger.debug("#{to_s}.has_access? => false why #{@roles.first}!=:all && #{!user.has_role?(*@roles)}")
        return false
      end

      if @block
        unless @block.call(model, user)
          #Tuersteher::TLogger.logger.debug("#{to_s}.has_access? => false why block return false")
          return false
        end
      end
      true
    end

    def to_s
      "ModelAccessRule[#{@clazz}, #{@access_type}, #{@roles.join(' ')}]"
    end

  end


  # ActiveRecord erweitern mit
  # Sicherheits-Check
  #
  #  class ActiveRecord::Base
  #    before_create {|model| SecurityModule::SecurityService.check_model_access model, :create }
  #    before_update {|model| SecurityModule::SecurityService.check_model_access model, :update }
  #    before_destroy{|model| SecurityModule::SecurityService.check_model_access model, :destroy }
  #  end


end
