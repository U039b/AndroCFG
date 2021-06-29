## {{app.name}}
We have statically analyzed the Android application {{app.name}} `{{app.package}}` available on [Google Play](https://play.google.com/store/apps/details?id={{app.package}}) in its version `{{app.version_name}}`.

### Permissions
This application requests the following permissions:

{{#each app.permissions}}
* `{{name}}` {{short}}
{{/each}}

### Behavior
By static analysis, it appears that:

{{#each rules}}
* {{rule.title}} *via* the following technical means [^{{rule.name}}]:
    {{#each findings}}
    * `{{call_by}}` provided by the company XXXX [^{{id}}]
    {{/each}}
{{/each}}


### Evidence files
{{#each rules}}
[^{{rule.name}}]: `{{{cfg_file}}}`
{{#each findings}}[^{{id}}]: `{{{evidence_file}}}`
{{/each}}
{{/each}}