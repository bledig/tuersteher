require "spec_helper"

module Tuersteher

  class Dashboard; end
  class Todo; end

  describe AccessRulesStorage do

    context "eval_rules" do
      before(:all) do
        rule_defs = <<-EOR
path('/').grant.method(:get)
path(:all).grant.role(:ADMIN)
path('/special').grant.extension(:special?, :area1)
path('/pictures') do
  grant.role(:admin)
  deny.role(:guest)
end

model(Dashboard).grant.method(:view)
model(Todo) do
  grant.method(:view)
  grant.method(:full_view).role(:ADMIN)
  grant.method(:update).role(:EDITOR).extension(:owned_by?) # calls Todo.owned_by?(current_user)
end
        EOR
        AccessRulesStorage.instance.eval_rules rule_defs
        @path_rules = AccessRulesStorage.instance.path_rules
        @model_rules = AccessRulesStorage.instance.model_rules
      end

      specify do
        @path_rules.should have(5).items
      end

      specify do
        @model_rules.should have(4).items
      end

      specify do
        AccessRules.path_access?(nil, '/')
      end

    end # of context "eval_rules"



    context "extend path with prefix" do
      context "eval_rules" do
        before(:all) do
          rule_defs = <<-EOR
  path(:all).grant.role(:ADMIN)
  path('/special').grant.role(:SPECIAL)
          EOR
          AccessRulesStorage.instance.eval_rules rule_defs
          AccessRulesStorage.instance.extend_path_rules_with_prefix('/test')
          @path_rules = AccessRulesStorage.instance.path_rules
        end

        specify{ @path_rules.first.path_spezification.should be_nil }
        specify{ @path_rules.last.path_spezification.path.should == '/test/special' }

      end
    end

  end # of describe AccessRulesStorage
end
