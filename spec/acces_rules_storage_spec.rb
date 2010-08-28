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

model(Dashboard).grant.permission(:view)
model(Todo) do
  grant.permission(:view)
  grant.permission(:full_view).role(:ADMIN)
  grant.permission(:update).role(:EDITOR).extension(:owned_by?) # calls Todo.owned_by?(current_user)
end
        EOR
        AccessRulesStorage.instance.eval_rules rule_defs
        @path_rules = AccessRulesStorage.instance.path_rules
        @model_rules = AccessRulesStorage.instance.model_rules
      end

      it "should have 3 path-rules" do
        @path_rules.should have(3).items
      end

      it "should have 4 model-rules" do
        @model_rules.should have(4).items
      end

    end # of context "eval_rules"

  end # of describe AccessRulesStorage
end
