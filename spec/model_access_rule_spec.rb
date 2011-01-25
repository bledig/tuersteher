require "spec_helper"

module Tuersteher

  describe ModelAccessRule do

    context "grant without user" do
      before do
        @rule = ModelAccessRule.new(String).grant.method(:all)
      end

      it "should fired without user" do
        @rule.fired?("test", :read, nil, nil).should be_true
      end

      it "should fired with user" do
        @user = stub('user')
        @rule.fired?("test", :read, @user, nil).should be_true
      end
    end


    context "grant with roles" do

      before(:all) do
        @rule = ModelAccessRule.new(String).grant.method(:read).role(:sysadmin).role(:admin)
      end

      context "for User with role :admin" do
        before do
          @user = stub('user')
          @user.stub(:has_role?) { |role| role==:admin }
        end

        it "should be fired for String-Object and access-type :read" do
          @rule.fired?("test", :read, @user, nil).should be_true
        end

        it "should not be fired for Non-String-Object" do
          @rule.fired?(12345, :read, @user, nil).should_not be_true
        end

        it "should not be fired for String-Object and other access-method as :read" do
          @rule.fired?("test", :delete, @user, nil).should_not be_true
        end
      end

      context "for User without role :admin" do
        before do
          @user = stub('user')
          @user.stub(:has_role?).and_return(false)
        end

        specify do
          @rule.fired?("test", :read, @user, nil).should_not be_true
        end
      end

      context "for :all Model-Instances" do
        before do
          @rule_all = ModelAccessRule.new(:all).grant.role(:admin)
          @user = stub('user')
        end

        it "should fired for user with role :admin" do
          @user.stub(:has_role?) { |role| role==:admin }
          @rule_all.fired?("test", :xyz, @user, nil).should be_true
        end

        it "should fired for user with role :admin" do
          @user.stub(:has_role?).and_return(false)
          @rule_all.fired?("test", :xyz, @user, nil).should_not be_true
        end
      end
    end # of context "grant with roles"


    context "deny with not.role" do
      before(:all) do
        @rule = ModelAccessRule.new(String).deny.method(:append).not.role(:admin)
        @user = stub('user')
      end

      it "should not fired for user with role :admin" do
        @user.stub(:has_role?){|role| role==:admin}
        @rule.fired?("/admin", :append, @user, nil).should_not be_true
      end

      it "should fired for user with role :user" do
        @user.stub(:has_role?){|role| role==:user}
        @rule.fired?("/admin", :append, @user, nil).should be_true
      end
    end # of context "deny with not.role"
    
    context "firing with user_extensions" do 
      
      def user
        @user ||= stub('user')
      end
      
      context "without params" do
      
        before(:all) do
          @rule = ModelAccessRule.new(String).grant.method(:append).user_extension(:has_permission?).user_extension(:is_allowed_to?)  
        end
      
        it "should fire for a user with given permissions" do
          user.stub(:has_permission?).and_return(true)
          user.stub(:is_allowed_to?).and_return(true)
          @rule.fired?("/admin", :append, user, nil).should be_true
        end  
      
        it "should not fire for a user without given permissions" do
          user.stub(:has_permission?).and_return(false)
          user.stub(:is_allowed_to?).and_return(false)
          @rule.fired?("/admin", :append, user, nil).should be_false
        end
        
        it "should not fire if one extension fails " do
          user.stub(:has_permission?).and_return(true)
          user.stub(:is_allowed_to?).and_return(false)
          @rule.fired?("/admin", :append, user, nil).should be_false
        end
      
      end #of context without params
      
      it "should raise an exception if the given option is not known" do
        lambda{ModelAccessRule.new(String).grant.method(:append).user_extension(:has_permission?, {:invalid => "option"})}.should raise_exception(RuntimeError, "option invalid not known")
      end  
       
      context "with value option" do  
        
        before(:all) do
          @rule = ModelAccessRule.new(String).grant.method(:append).user_extension(:has_permission?).user_extension(:permissions, {:value => [:append]})  
        end
        
        it "should fire if the given value is met" do
           user.stub(:has_permission?).and_return true
           user.stub(:permissions).and_return([:append])
           @rule.fired?("/admin", :append, user, nil).should be_true
        end
        
        it "should not fire if the given value is not met" do
          user.stub(:has_permission?).and_return true
          user.stub(:permissions).and_return([:other_method])
          @rule.fired?("/admin", :append, user, nil).should be_false
        end
        
      end #of context 'with value param'
      
      context "with object option" do
        
        before(:all) do
          @rule = ModelAccessRule.new(String).grant.method(:append).user_extension(:has_permission?).user_extension(:allowed_extension?, :object => true)
        end
        
        it "should fire if the the called extension returns true" do
          user.should_receive(:has_permission?).with(no_args()).and_return true
          user.stub(:allowed_extension?) { |given_string| given_string == "/admin" }
          @rule.fired?("/admin", :append, user, nil).should be_true
        end
        
        it "should not fire if the the called extension returns false" do
          user.stub(:has_permission?).and_return true 
          user.stub(:allowed_extension?) { |given_string| given_string != "/admin" }
          @rule.fired?("/admin", :append, user, nil).should be_false
        end
          
      end #of context 'with param option
       
      context "with args option" do
         
        before(:all) do
          @rule = ModelAccessRule.new(String).grant.method(:append).user_extension(:has_permission?).user_extension(:allowed_extension?, :args => ['extension'])
        end
        
        it "should fire if the the called extension returns true" do
          user.should_receive(:has_permission?).with(no_args()).and_return true
          user.stub(:allowed_extension?) { |given_string| given_string == "extension" }
          @rule.fired?("/admin", :append, user, nil).should be_true
        end
        
        it "should not fire if the the called extension returns false" do
          user.stub(:has_permission?).and_return true
          user.stub(:allowed_extension?) { |given_string| given_string != "extension" }
          @rule.fired?("/admin", :append, user, nil).should be_false
        end
        
      end
        
    end #of context 'firing user_extensions'
    
  end

end
