package barmanagement

import future.keywords

default allow := false

allow {
    print("Starting 'allow' rule evaluation")

    input_action := lower(input.resources.attributes.action)
    input_controller := lower(input.resources.attributes.controller)
    print("Input Action:", input_action)
    print("Input Controller:", input_controller)

    logical_action := determine_action(input_action, input_controller)
    print("Logical Action:", logical_action)

    logical_action == "OrderDrink"
    access_allowed_order_drink
} else {
    logical_action := determine_action(lower(input.resources.attributes.action), lower(input.resources.attributes.controller))
    logical_action == "AddDrink"
    access_allowed_add_drink
}
determine_action(action, controller) = result {
    action == "post"
    controller == "bar"
    result := "OrderDrink"
} else = result {
    action == "post"
    controller == "managebar"
    result := "AddDrink"
} else = "Unknown" {
    result := "Unknown"
}
access_allowed_order_drink {
    age := get_age_from_jwt
    print("Age from JWT:", age)

    drink_name := input.request.body.DrinkName
    lower_drink_name := lower(drink_name)
    print("Requested DrinkName:", drink_name)

    lower_drink_name != "beer"
    print("Access granted for drink:", drink_name)
}

access_allowed_order_drink {
    age := get_age_from_jwt
    print("Age from JWT:", age)

    drink_name := input.request.body.DrinkName
    lower_drink_name := lower(drink_name)
    print("Requested DrinkName:", drink_name)

    lower_drink_name == "beer"
    to_number(age) >= 16
    print("Access granted for Beer to user aged", age)
}
access_allowed_add_drink {
    roles := get_roles_from_jwt
    print("Roles from JWT:", roles)

    "bartender" == roles[_]
    print("User is a bartender")

}
get_age_from_jwt := age {
    print("Extracting Bearer token for age")

    auth_header := input.request.headers.Authorization
    print("Authorization header:", auth_header)

    auth_header != ""
    startswith(auth_header, "Bearer ")

    token := substring(auth_header, count("Bearer "), -1)
    print("Token for age:", token)

    [_, payload, _] := io.jwt.decode(token)
    print("JWT Payload for age:", payload)

    age := payload.age
    print("Extracted age:", age)
}

get_roles_from_jwt := roles {
    print("Extracting Bearer token for roles")

    auth_header := input.request.headers.Authorization
    print("Authorization header:", auth_header)

    auth_header != ""
    startswith(auth_header, "Bearer ")

    token := substring(auth_header, count("Bearer "), -1)
    print("Token for roles:", token)

    [_, payload, _] := io.jwt.decode(token)
    print("JWT Payload for roles:", payload)

    roles := payload.role
    print("Extracted roles:", roles)
}
