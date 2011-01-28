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


      context "without user" do
        it "should be true for this paths" do
          AccessRules.path_access?(nil, '/', :get).should be_true
        end

        it "should not be true for this paths" do
          AccessRules.path_access?(nil, '/xyz', :get).should_not be_true
          AccessRules.path_access?(nil, '/admin', :post).should_not be_true
        end
      end
    end


    context 'model_access?' do

      class SampleModel1; end
      class SampleModel2; end
      class SampleModel3; end
      class SampleModel4; end

      before do
        rules = [
          ModelAccessRule.new(:all).grant.role(:sysadmin),
          ModelAccessRule.new(SampleModel1).grant.method(:all),
          ModelAccessRule.new(SampleModel2).grant.method(:read),
          ModelAccessRule.new(SampleModel2).grant.method(:update).role(:user).extension(:owner?),
          ModelAccessRule.new(SampleModel2).deny.method(:create),
          ModelAccessRule.new(SampleModel2).grant.method(:all).role(:admin),
          ModelAccessRule.new(SampleModel3).grant.method(:read).method(:update).role(:user),
          ModelAccessRule.new(SampleModel3).grant.methods(:edit, :destroy).role(:user),
          ModelAccessRule.new(SampleModel3).deny.role(:user),
          ModelAccessRule.new(SampleModel4).grant.method(:details).roles(:user, :admin).user_extension(:is_admin?),
          ModelAccessRule.new(SampleModel4).grant.method(:change).roles(:user, :admin).user_extension(:has_permission_for?, :args => [:change]),
          ModelAccessRule.new(SampleModel4).grant.method(:action).roles(:user, :admin).user_extension(:allowed_action, :value => :action),
          ModelAccessRule.new(SampleModel4).grant.method(:update).roles(:user, :admin).user_extension(:owns_product?, :object => true),
          ModelAccessRule.new(SampleModel4).grant.method(:sell).roles(:user, :admin).extension(:owner?).user_extension(:owns_other?, :pass_args => true)
        ]
        AccessRulesStorage.instance.stub(:model_rules).and_return(rules)
        @user = stub('user')
        @model1 = SampleModel1.new
        @model2 = SampleModel2.new
        @model2.stub(:owner?).and_return(false)
        @model3 = SampleModel3.new
        @model4 = SampleModel4.new
        @model4.stub(:owner?){ |user| user == @user }
      end


      context "User with role :user" do
        before do
          @user.stub(:has_role?){|role| role==:user}
          @user.stub(:is_admin?).and_return(false)
          @user.stub(:has_permission_for?) { |action| action != :change }
          @user.stub(:allowed_action).and_return(:none)
          @user.stub(:owns_product?) { |product| product == @model4 }
          @user.stub(:owns_other?) { |other| other == @model3 }
        end

        it "should be true for this" do
          AccessRules.model_access?(@user, @model1, :xyz).should be_true
          @model2.stub(:owner?).and_return true
          AccessRules.model_access?(@user, @model2, :read).should be_true
          AccessRules.model_access?(@user, @model2, :update).should be_true
          AccessRules.model_access?(@user, @model3, :read).should be_true 
          AccessRules.model_access?(@user, @model3, :update).should be_true
          AccessRules.model_access?(@user, @model3, :edit).should be_true
          AccessRules.model_access?(@user, @model3, :destroy).should be_true
          AccessRules.model_access?(@user, @model4, :update).should be_true
          AccessRules.model_access?(@user, @model4, :sell, @model3).should be_true
        end

        it "should not be true for this" do
          AccessRules.model_access?(@user, @model2, :update).should_not be_true
          AccessRules.model_access?(@user, @model2, :delete).should_not be_true
          AccessRules.model_access?(@user, @model3, :delete).should_not be_true 
          AccessRules.model_access?(@user, @model3, :show).should_not be_true
          AccessRules.model_access?(@user, @model4, :details).should_not be_true
          AccessRules.model_access?(@user, @model4, :change).should_not be_true
          AccessRules.model_access?(@user, @model4, :action).should_not be_true
        end
      end


      context "User with role :admin" do
        before do
          @user.stub(:has_role?){|role| role==:admin}
          @user.stub(:is_admin?).and_return(true)
          @user.stub(:has_permission_for?) { |action| action == :change }
          @user.stub(:allowed_action).and_return(:action)
          @user.stub(:owns_product?) { |product| product != @model4 }
          @user.stub(:owns_other?) { |other| other != @model3 }
        end

        it "should be true for this" do
          AccessRules.model_access?(@user, @model1, :xyz).should be_true
          AccessRules.model_access?(@user, @model2, :read).should be_true
          AccessRules.model_access?(@user, @model2, :update).should be_true
          AccessRules.model_access?(@user, @model2, :delete).should be_true
          AccessRules.model_access?(@user, @model4, :details).should be_true
          AccessRules.model_access?(@user, @model4, :change).should be_true
          AccessRules.model_access?(@user, @model4, :action).should be_true
        end

        it "should not be true for this" do
          AccessRules.model_access?(@user, @model2, :create).should_not be_true
          AccessRules.model_access?(@user, @model4, :update).should_not be_true
          AccessRules.model_access?(@user, @model4, :sell, @model3).should_not be_true
        end
      end


      context "User with role :sysadmin" do
        before do
          @user.stub(:has_role?){|role| role==:sysadmin}
        end

        it "should be true for this" do
          AccessRules.model_access?(@user, "test", :xyz).should be_true
          AccessRules.model_access?(@user, @model1, :xyz).should be_true
          AccessRules.model_access?(@user, @model2, :read).should be_true
          AccessRules.model_access?(@user, @model2, :update).should be_true
          AccessRules.model_access?(@user, @model2, :delete).should be_true
          AccessRules.model_access?(@user, @model2, :create).should be_true
          AccessRules.model_access?(@user, @model4, :details).should be_true
          AccessRules.model_access?(@user, @model4, :change).should be_true
          AccessRules.model_access?(@user, @model4, :action).should be_true
          AccessRules.model_access?(@user, @model2, :create).should be_true
          AccessRules.model_access?(@user, @model4, :update).should be_true
          AccessRules.model_access?(@user, @model4, :sell, @model3).should be_true
          AccessRules.model_access?(@user, @model4, :sell).should be_true
        end
      end

      context "without user" do
        it "should be true for this models" do
          AccessRules.model_access?(nil, @model1, :xyz).should be_true
          AccessRules.model_access?(nil, @model2, :read).should be_true
        end

        it "should not be true for this models" do
          AccessRules.model_access?(nil, @model2, :update).should_not be_true
        end
      end
    end # of context 'model_access?'



    context 'purge_collection' do

      context 'without params' do

        class SampleModel
          def owner? user; false; end
        end

        before do
          rules = [
            ModelAccessRule.new(SampleModel).method(:update).role(:admin),
            ModelAccessRule.new(SampleModel).method(:update).role(:user).extension(:owner?),
          ]
          AccessRulesStorage.instance.stub(:model_rules).and_return(rules)
          @user = stub('user')
          @model1 = SampleModel.new
          @model2 = SampleModel.new
          @model3 = SampleModel.new
          @model3.stub(:owner?).and_return(true)
          @collection = [@model1, @model2, @model3]
        end

        it "Should return [@model3] for user with role=:user" do
          @user.stub(:has_role?){|role| role==:user}
          AccessRules.purge_collection(@user, @collection, :update).should == [@model3]
        end

        it "Should return all for user with role=:admin" do
          @user.stub(:has_role?){|role| role==:admin}
          AccessRules.purge_collection(@user, @collection, :update).should == @collection
        end

      end #without params

      context 'with args' do

        class Lcc
          def usable_in_view? view_name
            !(view_name == :svr)
          end
        end

        before do
          rules = [
            ModelAccessRule.new(Lcc).method(:use).extension(:usable_in_view?, :pass_args => true, :object => false)
          ]
          AccessRulesStorage.instance.stub(:model_rules).and_return(rules)
          @user = stub('user')
          @model1 = Lcc.new
          @model2 = Lcc.new
          @model3 = Lcc.new
          @collection = [ [@model1,[:seo_keywords]], [@model2,[:svr]], [@model3,[:sem_keywords]] ]
        end

        it "should return [@model1, @model3] for the user" do
          result_collection = AccessRules.purge_collection(@user, @collection, :use, :with_args => true)
          result_collection.should == [ [@model1,[:seo_keywords]], [@model3,[:sem_keywords]] ]
        end

      end

    end

  end
end
