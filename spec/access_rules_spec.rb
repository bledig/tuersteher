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

      before do
        rules = [
          ModelAccessRule.new(:all).grant.role(:sysadmin),
          ModelAccessRule.new(SampleModel1).grant.method(:all),
          ModelAccessRule.new(SampleModel2).grant.method(:read),
          ModelAccessRule.new(SampleModel2).grant.method(:update).role(:user).extension(:owner?),
          ModelAccessRule.new(SampleModel2).deny.method(:create),
          ModelAccessRule.new(SampleModel2).grant.method(:all).role(:admin),
        ]
        AccessRulesStorage.instance.stub(:model_rules).and_return(rules)
        @user = stub('user')
        @model1 = SampleModel1.new
        @model2 = SampleModel2.new
        @model2.stub(:owner?).and_return(false)
      end


      context "User with role :user" do
        before do
          @user.stub(:has_role?){|role| role==:user}
        end

        it "should be true for this" do
          AccessRules.model_access?(@user, @model1, :xyz).should be_true
          @model2.stub(:owner?).and_return true
          AccessRules.model_access?(@user, @model2, :read).should be_true
          AccessRules.model_access?(@user, @model2, :update).should be_true
        end

        it "should not be true for this" do
          AccessRules.model_access?(@user, @model2, :update).should_not be_true
          AccessRules.model_access?(@user, @model2, :delete).should_not be_true
        end
      end


      context "User with role :admin" do
        before do
          @user.stub(:has_role?){|role| role==:admin}
        end

        it "should be true for this" do
          AccessRules.model_access?(@user, @model1, :xyz).should be_true
          AccessRules.model_access?(@user, @model2, :read).should be_true
          AccessRules.model_access?(@user, @model2, :update).should be_true
          AccessRules.model_access?(@user, @model2, :delete).should be_true
        end

        it "should not be true for this" do
          AccessRules.model_access?(@user, @model2, :create).should_not be_true
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
    end

  end
end
