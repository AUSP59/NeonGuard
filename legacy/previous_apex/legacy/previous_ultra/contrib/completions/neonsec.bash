_neonsec(){ COMPREPLY=( $(compgen -W "analyze --input --format --window --rules --metrics --plugin --threads --outfmt --help" -- ${COMP_WORDS[COMP_CWORD]}) ); }; complete -F _neonsec neonsec;
