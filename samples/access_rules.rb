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
path('/pictures') do
  grant.role(:admin)
  deny.role(:guest)
end

#
# Model-Object-Zugriffsregeln
# Aufbau:
#   model(<ModelClass>).grant.method(<access-method>)[.role(<role>)][.extension(<method>[, <expected_value>])]
# or
#   model(<ModelClass>).deny.method(<access-method>)[.not][.role(<role>)][.extension(<method>[, <expected_value>])]
# or
#   model(<ModelClass> do
#     grant..method(<access-method>)[.role(<role>)][.extension(<method>[, <expected_value>])]
#     deny.method(<access-method>)[.role(<role>)][.extension(<method>[, <expected_value>])]
#     ...
#   end


model(Dashboard).grant.method(:view)

model(Todo) do
  grant.method(:view)
  grant.method(:full_view).role(:ADMIN)
  grant.method(:update).role(:EDITOR).extension(:owned_by?) # calls Todo.owned_by?(current_user)
  grant-method(:delete).not.role(:ADMIN)
end
