# derzeit genutzte Rollen:
# * ADMIN
# * EDITOR
# * APPROVER
# * USER


#
# Pfad-Zugriffsregeln
# Aufbau:  
#   path(<path>).grant[.method(<methode>)][.not][.role(<role>)][.extension(<ext_method>[, <expected_value>)]
# or
#   path(<path>).deny[.method(<methode>)][.not][.role(<role>)][.extension(<ext_method>[, <expected_value>)]
# with
#   <method>: HTTP-Method name as Symbol (:get, :put, :post, :delete) or :all 

path('/').grant.method(:get)
path(:all).grant.role(:ADMIN)
path('/user/lock').deny.role(:USER).role(:APPROVER)
path('/special').grant.extension(:special?, :area1)

#
# Model-Object-Zugriffsregeln
# Aufbau:
#   model(<ModelClass>).grant.permission(<permission>)[.role(<role>)][.extension(<method>[, <expected_value>])]
# or
#   model(<ModelClass>).deny.permission(<permission>)[.not][.role(<role>)][.extension(<method>[, <expected_value>])]
# or
#   model(<ModelClass> do
#     grant..permission(<permission>)[.role(<role>)][.extension(<method>[, <expected_value>])]
#     deny.permission(<permission>)[.role(<role>)][.extension(<method>[, <expected_value>])]
#     ...
#   end


model(Dashboard).grant.permission(:view)

model(Todo) do
  grant.permission(:view)
  grant.permission(:full_view).role(:ADMIN)
  grant.permission(:update).role(:EDITOR).extension(:owned_by?) # calls Todo.owned_by?(current_user)
  grant-permission(:delete).not.role(:ADMIN)
end
