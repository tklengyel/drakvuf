#include<json-c/json_object.h>

json_object *hijack_get_modules(json_object* candidates)
{
    json_object *modules;
    json_object_object_get_ex(candidates, "modules", &modules);
    return modules;
}

int hijack_get_num_modules(json_object *modules)
{
    return json_object_array_length(modules);
}


const char * hijack_get_module_name(json_object* module)
{
    json_object *mod_name;
    json_object_object_get_ex(module, "module-name", &mod_name);
    return json_object_get_string(mod_name);

}

const char * hijack_get_module_rekall_profile(json_object *module)
{
    json_object *mod_name;
    json_object_object_get_ex(module, "module-rekall-profile", &mod_name);
    return json_object_get_string(mod_name);
}

json_object * hijack_get_functions(json_object *module)
{
    json_object *functions;
    json_object_object_get_ex(module, "functions", &functions);
    return functions;
}

int hijack_get_num_functions(json_object *functions)
{

    return json_object_array_length(functions);
}

const char * hijack_get_fucntion_name(json_object *function)
{
    json_object *func_name;
    json_object_object_get_ex(function, "function-name", &func_name);
    return json_object_get_string(func_name);
}

json_object * hijack_get_arguments(json_object *function)
{
    json_object *args;
    json_object_object_get_ex(function, "arguments", &args);
    return args;
}
int hijack_get_num_arguments(json_object *args)
{
    return json_object_array_length(args);
}

const char * hijack_get_argument_type(json_object *args, int idx)
{
    json_object *arg;
    arg = json_object_array_get_idx(args,idx);
    return json_object_get_string(arg);
}