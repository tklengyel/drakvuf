code='''int main(void) { bool test[2] = { [1] = 1, [0] = 0 }; return 0; }'''
compiler = meson.get_compiler('cpp')
result = compiler.compiles(code)

if result == false
    error('Unsupported C++ compiler')
endif
