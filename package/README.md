# DRAKVUF DEB Package builder

## Design
The build process uses Docker to ensure some level of build reproducibility, agnostic from the particular type of Continous Integration being used. During the process, two Docker images are built:

* `Docker-xen` - intermediate, heavy image that contains all required build dependencies and Xen instalation; it should be cached and it is rebuilt only if the Xen submodule hash was changed
* `Docker-final` - the image that inherits from the previous one, installs LibVMI&DRAKVUF and does final packaging to `.deb` and `.tar.gz`.


## Manual run
If you have Docker, you can run the build process manually, even on your own computer.

```
# sh package/build.sh
```

The built package should appear in `package/out` directory.
