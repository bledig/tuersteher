require "spec_helper"

module Tuersteher

  describe ModelAccessRule do

    context "grant without user" do
      before do
        @rule = ModelAccessRule.new(String).grant.method(:all)
      end

      it "should fired without user" do
        @rule.fired?("test", :read, nil).should be_true
      end

      it "should fired with user" do
        @user = stub('user')
        @rule.fired?("test", :read, @user).should be_true
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
          @rule.fired?("test", :read, @user).should be_true
        end

        it "should not be fired for Non-String-Object" do
          @rule.fired?(12345, :read, @user).should_not be_true
        end

        it "should not be fired for String-Object and other access-method as :read" do
          @rule.fired?("test", :delete, @user).should_not be_true
        end
      end

      context "for User without role :admin" do
        before do
          @user = stub('user')
          @user.stub(:has_role?).and_return(false)
        end

        specify do
          @rule.fired?("test", :read, @user).should_not be_true
        end
      end

      context "for :all Model-Instances" do
        before do
          @rule_all = ModelAccessRule.new(:all).grant.role(:admin)
          @user = stub('user')
        end

        it "should fired for user with role :admin" do
          @user.stub(:has_role?) { |role| role==:admin }
          @rule_all.fired?("test", :xyz, @user).should be_true
        end

        it "should fired for user with role :admin" do
          @user.stub(:has_role?).and_return(false)
          @rule_all.fired?("test", :xyz, @user).should_not be_true
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
        @rule.fired?("/admin", :append, @user).should_not be_true
      end

      it "should fired for user with role :user" do
        @user.stub(:has_role?){|role| role==:user}
        @rule.fired?("/admin", :append, @user).should be_true
      end
    end # of context "deny with not.role"

  end

end
