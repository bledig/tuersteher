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

    attr_accessor :rules_config_file # to set own access_rules-path

    DEFAULT_RULES_CONFIG_FILE = 'access_rules.rb' # in config-dir

    def initialize
      @path_rules = []
      @model_rules = []
    end

    def path_rules
      read_rules unless @was_read
      @path_rules
    end

    def model_rules
      read_rules unless @was_read
      @model_rules
    end


    def eval_rules rules_definitions
      @path_rules = []
      @model_rules = []
      eval rules_definitions
      Tuersteher::TLogger.logger.info "Tuersteher::AccessRulesStorage: #{@path_rules.size} path-rules and #{@model_rules.size} model-rules"
    end

    # Laden der AccesRules aus den Dateien
    #  config/access_rules.rb
    def read_rules
      @rules_config_file ||= File.join(Rails.root, 'config', DEFAULT_RULES_CONFIG_FILE)
      rules_file = File.new @rules_config_file
      @was_read = false
      content = nil
      if @last_mtime.nil? || rules_file.mtime > @last_mtime
        @last_mtime = rules_file.mtime
        content = rules_file.read
      end
      rules_file.close
      if content
        eval_rules content
        @was_read = true
      end
    rescue => ex
      Tuersteher::TLogger.logger.error "Tuersteher::AccessRulesStorage - Error in rules: #{ex.message}\n\t"+ex.backtrace.join("\n\t")
    end

    # definiert HTTP-Pfad-basierende Zugriffsregel
    #
    # path:            :all fuer beliebig, sonst String mit der http-path beginnen muss,
    #                  wird als RegEX-Ausdruck ausgewertet
    def path url_path
      rule = PathAccessRule.new(url_path)
      @path_rules << rule
      rule
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
    def model model_class
      if block_given?
        @current_model_class = model_class
        yield
        @current_model_class = nil
      else
        rule = ModelAccessRule.new(model_class)
        @model_rules << rule
        rule
      end
    end

    def grant
      rule = ModelAccessRule.new(@current_model_class)
      @model_rules << rule
      rule.grant
    end

    def deny
      rule = ModelAccessRule.new(@current_model_class)
      @model_rules << rule
      rule.deny
    end

  end # of AccessRulesStorage


  class AccessRules

    # Pruefen Zugriff fuer eine Web-action
    # user        User, für den der Zugriff geprüft werden soll (muss Methode has_role? haben)
    # path        Pfad der Webresource (String)
    # method      http-Methode (:get, :put, :delete, :post), default ist :get
    #
    def self.path_access?(user, path, method = :get)
      rule = AccessRulesStorage.instance.path_rules.detect do |r|
        r.fired?(path, method, user)
      end
      if Tuersteher::TLogger.logger.debug?
        if rule.nil?
          s = 'denied'
        elsif rule.deny?
          s = "denied with #{rule}"
        else
          s = "granted with #{rule}"
        end
        Tuersteher::TLogger.logger.debug("Tuersteher: path_access?(#{path}, #{method})  =>  #{s}")
      end
      rule!=nil && !rule.deny?
    end


    # Pruefen Zugriff auf ein Model-Object
    #
    # user        User, für den der Zugriff geprüft werden soll (muss Methode has_role? haben)
    # model       das Model-Object
    # permission  das geforderte Zugriffsrecht (:create, :update, :destroy, :get)
    #
    # liefert true/false
    def self.model_access? user, model, permission
      raise "Wrong call! Use: model_access(model-instance-or-class, permission)" unless permission.is_a? Symbol
      return false unless model

      rule = AccessRulesStorage.instance.model_rules.detect do |rule|
        rule.fired? model, permission, user
      end
      access = rule && !rule.deny?
      if Tuersteher::TLogger.logger.debug?
        if model.instance_of?(Class)
          Tuersteher::TLogger.logger.debug("Tuersteher: model_access?(#{model}, #{permission}) =>  #{access || 'denied'} #{rule}")
        else
          Tuersteher::TLogger.logger.debug("Tuersteher: model_access?(#{model.class}(#{model.respond_to?(:id) ? model.id : model.object_id }), #{permission}) =>  #{access || 'denied'} #{rule}")
        end
      end
      access
    end

    # Bereinigen (entfernen) aller Objecte aus der angebenen Collection,
    # wo der angegebene User nicht das angegebene Recht hat
    #
    # liefert ein neues Array mit den Objecten, wo der spez. Zugriff arlaubt ist
    def self.purge_collection user, collection, permission
      collection.select{|model| model_access?(user, model, permission)}
    end
  end # of AccessRules



  # Module zum Include in Controllers
  # Dieser muss die folgenden Methoden bereitstellen:
  #
  #   current_user : akt. Login-User
  #   access_denied :  Methode aus dem authenticated_system, welche ein redirect zum login auslöst
  #
  # Der Loginuser muss fuer die hier benoetigte Funktionalitaet
  # die Methode:
  #   has_role?(role)  # role the Name of the Role as Symbol
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

      AccessRules.path_access? current_user, path, method
    end

    # Pruefen Zugriff auf ein Model-Object
    #
    # model       das Model-Object
    # permission  das geforderte Zugriffsrecht (:create, :update, :destroy, :get)
    #
    # liefert true/false
    def model_access? model, permission
      AccessRules.model_access? current_user, model, permission
    end

    # Bereinigen (entfernen) aller Objecte aus der angebenen Collection,
    # wo der akt. User nicht das angegebene Recht hat
    #
    # liefert ein neues Array mit den Objecten, wo der spez. Zugriff arlaubt ist
    def self.purge_collection collection, permission
      AccessRules.purge_collection(current_user, collection, permission)
    end


    def self.included(base)
      base.class_eval do
        # Diese Methoden  auch als Helper fuer die Views bereitstellen
        helper_method :path_access?, :model_access?, :purge_collection
      end
    end

    protected

    # Pruefen, ob Zugriff des current_user
    # fuer aktullen Request erlaubt ist
    def check_access

      # im dev-mode rules bei jeden request auf Änderungen prüfen
      AccessRulesStorage.instance.read_rules if Rails.env=='development'

      req_method = request.method.downcase.to_sym
      unless path_access?(request.request_uri, req_method)
        msg = "Tuersteher#check_access: access denied for #{request.request_uri} :#{req_method}"
        Tuersteher::TLogger.logger.warn msg
        logger.warn msg  # log message also for Rails-Default logger
        access_denied  # Methode aus dem authenticated_system, welche ein redirect zum login auslöst
      end
    end

  end

  # Astracte base class for Access-Rules
  class BaseAccessRule

    def initialize
      @roles = []
    end

    # add role
    def role(role_name)
      raise "wrong role '#{role_name}'! Must be a symbol " unless role_name.is_a?(Symbol)
      @roles << role_name
      self
    end


    def extension method_name, methode_parameter=nil
      @check_extensions ||= {}
      @check_extensions[method_name] = methode_parameter
      self
    end

    def grant
      self
    end

    def deny
      @deny = true
      self
    end

    def deny?
      @deny
    end

    protected

    def grant_role? user
      return true if @roles.empty?
      return false if user.nil?
      @roles.each do |role|
        return true if user.has_role?(role)
      end
      false
    end

  end # of BaseAccessRule


  class PathAccessRule < BaseAccessRule

    METHOD_NAMES = [:get, :edit, :put, :delete, :post, :all].freeze


    # Zugriffsregel
    #
    # path          :all fuer beliebig, sonst String mit der http-path beginnen muss
    #
    def initialize(path)
      raise "wrong path '#{path}'! Must be a String or :all ." unless path==:all or path.is_a?(String)
      super()
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
      @http_method = :all
    end

    # set http-methode
    # http_method        http-Method, allowed is :get, :put, :delete, :post, :all
    def method(http_method)
      raise "wrong method '#{http_method}'! Must be #{METHOD_NAMES.join(', ')} !" unless METHOD_NAMES.include?(http_method)
      @http_method = http_method
      self
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

      if @http_method!=:all && @http_method != method
        return false
      end

      if !@roles.empty? && (user.nil? || !user.has_role?(*@roles))
        #Tuersteher::TLogger.logger.debug("#{to_s}.has_access? => false why #{@roles.first}!=:all && #{!user.has_role?(*@roles)}")
        return false
      end

      return false unless grant_extension?(user)

      true
    end


    def to_s
      s = "PathAccesRule[#{@deny ? 'DENY ' : ''}#{@path}, #{@http_method}, #{@roles.join(' ')}"
      s << " #{@check_extensions.inspect}" if @check_extensions
      s << ']'
      s
    end

    private

    def grant_extension? user
      return true if @check_extensions.nil?
      return false if user.nil?  # check_extensions need a user
      @check_extensions.each do |key, value|
        unless user.respond_to?(key)
          Tuersteher::TLogger.logger.warn("#{to_s}.fired? => false why user have not check-extension method '#{key}'!")
          return false
        end
        if value
          return false unless user.send(key,value)
        else
          return false unless user.send(key)
        end
      end
      true
    end

  end



  class ModelAccessRule < BaseAccessRule

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
    def initialize(clazz)
      raise "wrong clazz '#{clazz}'! Must be a Class or :all ." unless clazz==:all or clazz.is_a?(Class)
      super()
      @clazz = clazz.instance_of?(Symbol) ? clazz : clazz.to_s
    end


    def permission permission_name
      @permission = permission_name
      self
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
    def fired? model, perm, user
      user = nil if user==:false # manche Authenticate-System setzen den user auf :false
      debugger
      m_class = model.instance_of?(Class) ? model : model.class
      if @clazz!=m_class.to_s && @clazz!=:all
        #Tuersteher::TLogger.logger.debug("#{to_s}.has_access? => false why #{@clazz}!=#{model.class.to_s} && #{@clazz}!=:all")
        return false
      end

      if @permission!=:all && @permission!=perm
        #Tuersteher::TLogger.logger.debug("#{to_s}.has_access? => false why #{@access_type}!=:all && #{@access_type}!=#{perm}")
        return false
      end

      return false unless grant_role?(user)
      return false unless grant_extension?(user, model)
      true
    end

    def to_s
      s = "ModelAccessRule[#{@deny ? 'DENY ' : ''}#{@clazz}, #{@permission}, #{@roles.join(' ')}"
      s << " #{@check_extensions.inspect}" if @check_extensions
      s << ']'
      s
    end

    private

    def grant_extension? user, model
      return true if @check_extensions.nil?
      return false if model.nil?  # check_extensions need a model
      return false if model.instance_of?(Class) # no Extension-Call if model is a Class-Instance
      @check_extensions.each do |key, value|
        unless model.respond_to?(key)
          Tuersteher::TLogger.logger.warn("#{to_s}.fired? => false why model-onject have not check-extension method '#{key}'!")
          return false
        end
        if value
          return false unless model.send(key,user,value)
        else
          return false unless model.send(key,user)
        end
      end
      true
    end

  end


end
