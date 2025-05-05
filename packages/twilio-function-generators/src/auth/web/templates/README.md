# Templates Directory

## Overview

This directory holds the raw handlebar templates used by the solution along with a `complied.ts` 
file that holds the compiled versions of the templates for use within the solution.

## Usage

Any file in this directory that ends with the `.hbs` file extension will be picked up by the
`precompile-templates` script and an exported property in the `compiled.ts` file will be added.

If you made a change to one of the `.hbs` files in this directory please run the following script
to pre-compile the templates before committing changes to source control or using in development / production.

 ```bash
 yarn precompile-templates
 ```

**Note:** script will also run as part of the `build` script.
