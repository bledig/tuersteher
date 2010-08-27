require "spec_helper"



module Tuersteher

  describe AccessRules do

    context 'path_access?' do
      before do
        rules = [
          PathAccessRule.new('/'),
          PathAccessRule.new('/admin').role(:admin),
          PathAccessRule.new('/images').method(:get),
          PathAccessRule.new('/status').method(:get).role(:system)
        ]
        AccessRulesStorage.instance.stub(:path_rules).and_return(rules)
        @user = stub('user')
      end


      context "User with role :user" do
        before do
          @user.stub(:has_role?){|role| role==:user}
        end

        it "should be true for this paths" do
          AccessRules.path_access?(@user, '/', :get).should be_true
          AccessRules.path_access?(@user, '/', :post).should be_true
          AccessRules.path_access?(@user, '/images', :get).should be_true
        end

        it "should not be true for this paths" do
          AccessRules.path_access?(@user, '/admin', :get).should_not be_true
          AccessRules.path_access?(@user, '/images', :post).should_not be_true
          AccessRules.path_access?(@user, '/status', :get).should_not be_true
        end
      end


      context "User with role :admin" do
        before do
          @user.stub(:has_role?){|role| role==:admin}
        end

        it "should be true for this paths" do
          AccessRules.path_access?(@user, '/', :get).should be_true
          AccessRules.path_access?(@user, '/admin', :post).should be_true
          AccessRules.path_access?(@user, '/images', :get).should be_true
        end

        it "should not be true for this paths" do
          AccessRules.path_access?(@user, '/xyz', :get).should_not be_true
          AccessRules.path_access?(@user, '/images', :post).should_not be_true
          AccessRules.path_access?(@user, '/status', :get).should_not be_true
        end
      end


      context "User with role :system" do
        before do
          @user.stub(:has_role?){|role| role==:system}
        end

        it "should be true for this paths" do
          AccessRules.path_access?(@user, '/', :get).should be_true
          AccessRules.path_access?(@user, '/status', :get).should be_true
        end

        it "should not be true for this paths" do
          AccessRules.path_access?(@user, '/xyz', :get).should_not be_true
          AccessRules.path_access?(@user, '/admin', :post).should_not be_true
        end
      end
    end


    context 'model_access?' do
      before do
        deny_rule =  ModelAccessRule.new(String, :update, :admin){|model, user| model=='no admin'}
        deny_rule.deny = true
        rules = [
          ModelAccessRule.new(Fixnum, :all, :all),
          ModelAccessRule.new(String, :read, :all),
          deny_rule,
          ModelAccessRule.new(String, :update, :admin),
          ModelAccessRule.new(String, :update, :user){|model, user| model=='test'},
        ]
        AccessRulesStorage.instance.stub(:model_rules).and_return(rules)
        @user = stub('user')
      end


      context "User with role :user" do
        before do
          @user.stub(:has_role?){|role| role==:user}
        end

        it "should be true for this" do
          AccessRules.model_access?(@user, 1234, :xyz).should be_true
          AccessRules.model_access?(@user, 'xyz', :read).should be_true
          AccessRules.model_access?(@user, 'test', :update).should be_true
        end

        it "should not be true for this" do
          AccessRules.model_access?(@user, 'xyz', :update).should_not be_true
        end
      end


      context "User with role :admin" do
        before do
          @user.stub(:has_role?){|role| role==:admin}
        end

        it "should be true for this" do
          AccessRules.model_access?(@user, 1234, :xyz).should be_true
          AccessRules.model_access?(@user, 'xyz', :read).should be_true
          AccessRules.model_access?(@user, 'xyz', :update).should be_true
        end

        it "should not be true for this" do
          puts "\n===========================================================\n\n"
          AccessRules.model_access?(@user, 'no admin', :update).should_not be_true
        end
      end
    end



    context 'purge_collection' do
      before do
        deny_rule =  ModelAccessRule.new(String, :update, :admin){|model, user| model=='no admin'}
        deny_rule.deny = true
        rules = [
          deny_rule,
          ModelAccessRule.new(String, :update, :admin),
          ModelAccessRule.new(String, :update, :user){|model, user| model=='test'},
        ]
        AccessRulesStorage.instance.stub(:model_rules).and_return(rules)
        @user = stub('user')
        @collection = ['xyz', 'test', 'no admin']
      end

      it "Should return ['test'] for user with role=:user" do
        @user.stub(:has_role?){|role| role==:user}
        AccessRules.purge_collection(@user, @collection, :update).should == ['test']
      end

      it "Should return ['xyz', test'] for user with role=:admin" do
        @user.stub(:has_role?){|role| role==:admin}
        AccessRules.purge_collection(@user, @collection, :update).should == ['xyz', 'test']
      end
    end

  end
end