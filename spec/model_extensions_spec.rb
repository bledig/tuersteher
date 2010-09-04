require "spec_helper"

module Tuersteher

  describe ModelExtensions do

    class SampleModel
      include ModelExtensions

      def deactived
        check_access :deactived
      end
    end


    before do
      rules = [ModelAccessRule.new(SampleModel).grant.method(:deactived).role(:admin)]
      AccessRulesStorage.instance.stub(:model_rules).and_return(rules)
      @user = stub('user')
      Thread.current[:user] = @user
    end


    context "check_access" do

      it "should not raise a Error for user with role :admin" do
        @user.stub(:has_role?){|role| role==:admin}
        model = SampleModel.new
        model.deactived
      end

      it "should raise a SecurityError for user with not role :admin" do
        @user.stub(:has_role?){|role| role==:user}
        model = SampleModel.new
        expect{ model.deactived }.to raise_error(SecurityError)
      end

    end # of context "grant with roles"


    context "purge_collection" do

      it "should purge nothing for user with role :admin" do
        @user.stub(:has_role?){|role| role==:admin}
        list = [SampleModel.new]
        SampleModel.purge_collection(list, :deactived).should == list
      end

      it "should purge all for user with not role :admin" do
        @user.stub(:has_role?){|role| role==:user}
        list = [SampleModel.new]
        SampleModel.purge_collection(list, :deactived).should == []
      end

    end # of  context "purge_collection"
  end
end

