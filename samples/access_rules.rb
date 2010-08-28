# derzeit genutzte Rollen:
# * ADMIN
# * EDITOR
# * APPROVER
# * USER


#
# Pfad-Zugriffsregeln
# Aufbau:  
#   Path : URL-Pfad, wird als regex ausgewertet
#   Methode : :all, :get, :put, :post, :delete oder :edit 
#   roles :Liste der berechtigten Rollen (es können mehrere Rollen durch Komma getrennt angegeben werden)
#

path('/').grant.method(:get)
path(:all).grant.role(:ADMIN)
path('/user/lock').deny.role(:USER).role(:APPROVER)
path('/special').grant.extension(:special?, :area1)

#
# Model-Object-Zugriffsregeln
# Aufbau:
#   Model-Klasse : Klasse des Models
#   Zugriffsart : frei definierbares Symbol, empfohlen :update, :create, :destroy
#   Roles : Aufzählung der Rollen
#   Block : optionaler Block, diesem wird die Model-Instance und der User als Parameter bereitgestellt

#grant_model String, :view, :all
#grant_model String, :view, :ADMIN, :EDITOR
#grant_model String, :update, :EDITOR do |model, user| model == user.name end

model(Todo).method(:view)
model(Todo).method(:full_view).role(:ADMIN)
model(Todo).method(:update).role(:EDITOR).extension(:owned_by?) # calls String.owned_by?(current_user)

model(Todo) do
  method(:view).all
  
end