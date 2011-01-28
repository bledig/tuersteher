require "spec_helper"

module Tuersteher

  describe ModelExtensions do

    class SampleModel
      include ModelExtensions

      def deactived
        check_access :deactived
      end
    end

    class SampleModel2
      include ModelExtensions

      def var= value
        check_access :var=, value
      end

      def allow_setup_var_with? value
        value == :right_value
      end
    end


    before do
      rules = [ModelAccessRule.new(SampleModel).grant.method(:deactived).role(:admin)]
      rules << ModelAccessRule.new(SampleModel2).grant.method(:var=).role(:user).extension(:allow_setup_var_with?, :object => false, :pass_args => true)
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

    context "check_access with environment" do

      it "should not raise for a user with right value" do
        @user.stub(:has_role?) { |role| role==:user }
        model = SampleModel2.new
        lambda{ model.var= :right_value }.should_not raise_exception(SecurityError)
      end

      it "should raise for a user with not right value" do
        @user.stub(:has_role?) { |role| role==:user }
        model = SampleModel2.new
        lambda{ model.var= :wrong_value }.should raise_exception(SecurityError)
      end

      it "should raise for a user with wrong role" do
        @user.stub(:has_role?) { |role| !role==:user }
        model = SampleModel2.new
        lambda{ model.var= :right_value }.should raise_exception(SecurityError)
      end

    end

    context "purge_collection" do

      context "list of models" do

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

      end

      context "list of models with args" do

        it "should purge the one with wrong input and the one without any" do
          @user.stub(:has_role?) { |role| role==:user }
          first_model = SampleModel2.new
          second_model = SampleModel2.new
          third_model = SampleModel2.new
          list = [[first_model,[:wrong_value]], [second_model,[:right_value]], third_model ]
          SampleModel2.purge_collection(list, :var=, :with_args => true).should == [[second_model,[:right_value]]]
        end

        it "should purge a list of models with a given env" do
          @user.stub(:has_role?) { |role| role==:user }
          first_model = SampleModel2.new
          second_model = SampleModel2.new
          second_model.stub(:allow_setup_var_with?).and_return(false)
          list = [first_model, second_model]
          SampleModel2.purge_collection(list, :var=, :right_value).should == [first_model]
        end

        it "should purge a list of values with a given env array" do
          @user.stub(:has_role?) { |role| role==:user }
          list_of_values = [:right_value, :wrong_value]
          SampleModel2.purge_collection(SampleModel2.new, :var=, list_of_values).should == [:right_value]
        end

      end

    end # of  context "purge_collection"
  end
end

