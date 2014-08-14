require "spec_helper"

module Tuersteher

  describe PathAccessRule do

    context "grant" do
      before(:all) do
        @rule = PathAccessRule.new('/admin').grant.method(:get).role(:sysadmin).role(:admin)
      end


      context "for User with role :admin" do
        before do
          @user = stub('user')
          @user.stub(:has_role?){|role| role==:admin}
        end

        it "should be fired for path='/admin/xyz' and method :get" do
          @rule.fired?("/admin/xyz", :get, @user).should be_true
        end

        it "should not be fired for other path" do
          @rule.fired?('/todos/admin', :get, @user).should_not be_true
        end

        it "should not be fired for other method as :get" do
          @rule.fired?("/admin/xyz", :post, @user).should_not be_true
        end
      end


      context "for User without role :admin" do
        before do
          @user = stub('user')
          @user.stub(:has_role?).and_return(false)
        end

        it "should not be fired for correct path and method" do
          @rule.fired?("/admin/xyz", :get, @user).should_not be_true
        end
      end


      context "Rule with :all as Path-Matcher" do
        before(:all) do
          @rule = PathAccessRule.new(:all).method(:get).role(:sysadmin).role(:admin)
          @user = stub('user')
          @user.stub(:has_role?).and_return(true)
        end

        it "should fired for several paths" do
          @rule.fired?("/admin/xyz", :get, @user).should be_true
          @rule.fired?("/xyz", :get, @user).should be_true
          @rule.fired?("/", :get, @user).should be_true
        end

        it "should not be fired with other method" do
          @rule.fired?("/admin/xyz", :post, @user).should_not be_true
        end
      end


      context "Rule with no Methode spezifed => all methods allowed" do
        before(:all) do
          @rule = PathAccessRule.new('/admin').role(:sysadmin).role(:admin)
          @user = stub('user')
          @user.stub(:has_role?).and_return(true)
        end

        it "should fired for several methods" do
          @rule.fired?("/admin/xyz", :get, @user).should be_true
          @rule.fired?("/admin/xyz", :post, @user).should be_true
          @rule.fired?("/admin/xyz", :put, @user).should be_true
          @rule.fired?("/admin/xyz", :delete, @user).should be_true
        end

        it "should not be fired with other path" do
          @rule.fired?("/xyz", :post, @user).should_not be_true
        end
      end


      context "Rule with no role spezifed => no role needed" do
        before(:all) do
          @rule = PathAccessRule.new('/public').method(:get)
          @user = stub('user')
          @user.stub(:has_role?).and_return(false)
        end

        it "should fired for user with no roles" do
          @rule.fired?("/public/xyz", :get, @user).should be_true
        end

        it "should fired for non user" do
          @rule.fired?("/public/xyz", :get, nil).should be_true
        end

        it "should not be fired with other path" do
          @rule.fired?("/xyz", :get, @user).should_not be_true
        end
      end


      context "Rule with extension" do
        before(:all) do
          @rule = PathAccessRule.new('/admin').method(:get).extension(:modul_function?, :testvalue)
          @rule2 = PathAccessRule.new('/admin').method(:get).extension(:modul_function2?)
          @user = stub('user')
          @user.stub(:has_role?).and_return(false)
        end

        it "should not be fired with user have not the check_extension" do
          @rule.fired?("/admin", :get, @user).should_not be_true
        end

        it "should fired for user with true for check-extension" do
          @user.should_receive(:modul_function?).with(:testvalue).and_return(true)
          @rule.fired?("/admin/xyz", :get, @user).should be_true
        end

        it "should not be fired for user with false for check-extension" do
          @user.should_receive(:modul_function?).with(:testvalue).and_return(false)
          @rule.fired?("/admin/xyz", :get, @user).should_not be_true
        end

        it "should fired for rule2 and user with true for check-extension" do
          @user.should_receive(:modul_function2?).and_return(true)
          @rule2.fired?("/admin/xyz", :get, @user).should be_true
        end
      end
    end # of context "grant" do


    context "deny" do
      before(:all) do
        @rule = PathAccessRule.new('/admin').deny.role(:user)
        @user = stub('user')
      end

      it "should fired for user with role :user" do
        @user.stub(:has_role?){|role| role==:user}
        @rule.fired?("/admin", :get, @user).should be_true
      end

      it "should not fired for user with role :admin" do
        @user.stub(:has_role?){|role| role==:admin}
        @rule.fired?("/admin", :get, @user).should_not be_true
      end
    end # of context "deny" do


    context "with not" do
      context "as prefix for role" do
        before(:all) do
          @rule = PathAccessRule.new('/admin').deny.not.role(:admin)
          @user = stub('user')
        end

        it "should not fired for user with role :admin" do
          @user.stub(:has_role?){|role| role==:admin}
          @rule.fired?("/admin", :get, @user).should_not be_true
        end

        it "should fired for user with role :user" do
          @user.stub(:has_role?){|role| role==:user}
          @rule.fired?("/admin", :get, @user).should be_true
        end
      end

      context "as prefix for extension" do
        before(:all) do
          @rule = PathAccessRule.new('/admin').grant.role(:admin).not.extension(:login_ctx_method)
          @user = stub('user')
        end

        it "should fired for user with role :admin and false for extension" do
          @user.stub(:has_role?){|role| role==:admin}
          @user.should_receive(:login_ctx_method).and_return(false)
          @rule.fired?("/admin", :get, @user).should be_true
        end

        it "should not fired for user with role :admin and true for extension" do
          @user.stub(:has_role?){|role| role==:admin}
          @user.should_receive(:login_ctx_method).and_return(true)
          @rule.fired?("/admin", :get, @user).should_not be_true
        end

        it "should not fired for user with role :user" do
          @user.stub(:has_role?){|role| role==:user}
          @rule.fired?("/admin", :get, @user).should be_false
        end

      end
    end # of context "not" do


    context "add multiple roles" do
      before(:all) do
        @rule = PathAccessRule.new('/admin').roles(:admin1, :admin2).roles([:s1, :s2])
        @user = stub('user')
      end

      it "should fired for user with role which specified in the rule" do
        [:admin1, :admin2, :s1, :s2].each do |role_name|
          @user.stub(:has_role?){|role| role==role_name}
          @rule.fired?("/admin", :get, @user).should be_true
        end
      end

      it "should not fired for user with role :user" do
        @user.stub(:has_role?){|role| role==:user}
        @rule.fired?("/admin", :get, @user).should_not be_true
      end
    end
  end
end
