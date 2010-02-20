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
grant_path '/', :get, :all
grant_path :all, :all, :ADMIN
deny_path '/user/lock', :user

#
# Model-Object-Zugriffsregeln
# Aufbau:
#   Model-Klasse : Klasse des Models
#   Zugriffsart : frei definierbares Symbol, empfohlen :update, :create, :destroy
#   Roles : Aufzählung der Rollen
#   Block : optionaler Block, diesem wird die Model-Instance und der User als Parameter bereitgestellt

grant_model String, :view, :all
grant_model String, :view, :ADMIN, :EDITOR
grant_model String, :update, :EDITOR do |model, user| model == user.name end

