package TagFilter;
use strict;

use Carp ();
use base qw(HTML::Parser);
use vars qw($VERSION);

$VERSION = '0.04';  # $Date: 2001/09/18 $

=head1 NAME

TagFilter - An HTML::Parser-based selective tag remover

=head1 SYNOPSIS

	use TagFilter;
	$filter = new TagFilter;
	# or
	$filter = TagFilter->new(allow=>{...}, deny=>{...});
	$filter->parse($dirty_html);
	$clean_html = $filter->output();

=head1 DESCRIPTION

TagFilter is a subclass of HTML::Parser with a single purpose: it will remove unwanted html tags and attributes from a piece of text. It can act in a more or less fine-grained way - you can specify permitted tags, permitted attributes of each tag, and permitted values for each attribute in as much detail as you like.

One day it will try and find a place in the HTML:: namespace, but it needs a spot of public humiliation first.

So. Tags which are not allowed are removed. Tags which are allowed are trimmed down to only the attributes which are allowed for each tag. It is possible to allow all or no attributes from a tag, or to allow all or no values for an attribute, and so on.

TagFilter doesn't do anything to or with the text between bits of markup: it's only interested in the tags.

The original purpose for this was to screen user input. In that setting you'll probably find that just using:

	my $filter = new TagFilter;
	$filter->parse($my_text);
	put_in_database($filter->output());

will do. However, it can also be used for display processes (eg text-only translation) or cleanup (eg removal of old javascript). In those cases you'll probably want to override the default rule set with a small number of denial rules. 

	my $filter = TagFilter->new(deny => {img => {'all'}});
	$filter->parse($my_text);
	print $filter->output();

Will strip out all images, for example, but leave everything else untouched.

=head1 CONFIGURATION

Configuration is fairly simple. You have three options:

=head2 use the defaults

which will produce safe but still formatted html, without images, tables, javascript or much else apart from inline text formatting and links.

=head2 selectively override the defaults

use the allow_tags and deny_tags methods to pass in one or more tag settings. eg:

	$filter->allow_tags({ p => { class=> ['lurid','sombre','plain']} });

will mean that all attributes other than class="lurid|sombre|plain" will be removed from <p> tags. See below for more about specifying rules.

=head2 supply your own configuration

To override the defaults completely, supply the constructor with some rules:

	my $filter = TagFilter->new( allow=>{ p => { class=> ['lurid','sombre','plain']} });

Only the rules you supply in this form will be applied. You can achieve the same thing after construction by first clearing the rule set:

	my $filter = TagFilter->new();
	$filter->allow_tags();
	$filter->allow_tags({ p => { align=> ['left','right','center']} });

Future versions are intended to offer a more sophisticated rule system, allowing you to specify combinations of attributes, ranges for values and generally match names in a more fuzzy way. The simple hash thing will still work, though.

=head1 RULES

Each element is tested as it is encountered, in two stages:

=over 4

=item tag filter

Just checks that this tag is permitted, and blocks the whole thing if not. Applied to both opening and closing tags.

=item attribute filter

Any tag that passes the tag filter will remain in the text, but the attribute filter will strip out of it any attributes that are not permitted, or which have values that are not permitted for that tag/attribute combination.

=back

=head2 format for rules

There are two kinds of rule: permissions and denials. They work as you'd expect, and can coexist, but they're not quite symmetrical. Denial rules are intended to complement permission rules, so that they can provide a kind of compound 'unless'.

* If there are any 'permission' rules, then everything that doesn't satisfy any of them is eliminated.

* If there are any 'deny' rules, then anything that satisfies any of them is eliminated.

* If there are both denial and permission rules, then everything either satisfies a denial rule or fails to satisfy any of the permission rules is eliminated.

* If there is neither kind, we strip out everything just to be on the safe side.

The two most likely setups are 

1. a full set of permission rules and maybe a couple of denial rules to eliminate pet hates.

2. no permission rules at all and a small set of denial rules to remove particular tags.

Rules are passed in as a HoHoL:

	{ tag name->{attribute name}->[valuelist] }

There are three reserved words: 'any and 'none' stand respectively for 'anything is permitted' and 'nothing is permitted', or if in denial: 'anything is removed' and 'nothing is removed'. 'all' is only used in denial rules and it indicates that the whole tag should be stripped out: see below for an explanation and some mumbled excuses.

For example:

	$filter->allow_tags({ p => { any => [] });

Will permit <p> tags with any attributes. For clarity's sake it may be shortened to:

	$filter->allow_tags({ p => { 'any' });

but note that in the absence of the => the quotes are required. And

	$filter->allow_tags({ p => { 'none' });

Will allow <p> tags to remain in the text, but all attributes will be removed. The same rules apply at all levels in the tag/attribute/value hierarchy, so you can say things like:

	$filter->allow_tags({ any => { align => [qw(left center right)] });
	$filter->allow_tags({ p => { align => ['any'] });

but that last is more easily written

	$filter->allow_tags({ p => { 'align' });

=head2 examples

To indicate that a link destination is ok and you don't mind what value it takes:

	$filter->allow_tags({ a => { 'href' } });

To limit the values an attribute can take:

	$filter->allow_tags({ a => { class => [qw(big small middling)] } });

To clear all permissions:

	$filter->allow_tags({});

To remove all onClicks from links but allow all targets:

	$filter->allow_tags({ a => { onClick => ['none'], target => [], } });

You can combine allows and denies to create 'unless' rules:

	$filter->allow_tags({ a => { 'any' } });
	$filter->deny_tags({ a => { 'onClick' } });

Will remove only the onClick attribute of a link, allowing everything else through. If this was your only purpose, you could achieve the same thing just with the denial rule and an empty permission set, but if there's other stuff going on then you probably need this combination.

=head2 order of application

denial rules are applied first. we take out whatever you specify in deny, then take out whatever you don't specify in allow, unless the allow set is empty, in which case we ignore it. If both sets are empty, no tags gets through.

(We prefer to err on the side of less markup, but I expect this will be configurable soon.)

=head2 oddities

Only one deliberate one, so far. The main asymmetry between permission and denial rules is that from

	allow_tags->{ p => {...}}

it follows that p tags are permitted, but the reverse is not true: 

	deny_tags->{ p => {...}}

doesn't imply that p tags are removed. It would be silly to detail the attribute you didn't want and thereby remove the whole tag. If you want to use a denial rule to eliminate a whole tag, you have to say so explicitly:

	deny_tags->{ p => {'all'}}

will remove every <p> tag, whereas

	deny_tags->{ p => {'any'}}

will just remove all the attributes from <p> tags. Not very pretty, I know. It's likely to change, but probably not until after we've invented a system for supplying rules in a more readable format.

=cut

my $allowed_by_default = {
	h1 => { 'none' },
	h2 => { 'none' },
	h3 => { 'none' },
	h4 => { 'none' },
	h5 => { 'none' },
	p => { 'none' },
	a => { href => [], name => [], target => [] },
	br => { clear => [qw(left right all)]},
	ul =>{ 'type' },
	li =>{ 'type' },
	ol => { 'none' },
	em => { 'none' },
	i => { 'none' },
	b => { 'none' },
	tt => { 'none' },
	code => { 'none' },
	blockquote => { 'none'},
	img => { 'any' },
	any => { align => [qw(left right center)]  },
};

my $denied_by_default = {
	blink => { 'all' },
	marquee => { 'all' },
	img => { 'all' },
	any => { style => [], class => [], onMouseover => [], onClick => [], onMouseout => [], },
};

sub new {
    my $class = shift;
    
    my $filter = $class->SUPER::new(api_version => 3);

    $filter->SUPER::handler(start => "_filter_start", 'self, tagname, attr');
    $filter->SUPER::handler(end =>  "_filter_end", 'self, tagname');
    $filter->SUPER::handler(default => "_add_to_output", "self, text");
	
	my $config = {@_};
	$filter->{_allows} = {};
	$filter->{_denies} = {};

	$config->{allow} ||= $allowed_by_default;
	$config->{deny} ||= $denied_by_default;
	$filter->allow_tags($config->{allow});
	$filter->deny_tags($config->{deny});
	
	return $filter;
}

# _filter_start(): the designated handler for start tags: tests them against the _tag_ok() function
# and then, if they pass, each of their attributes against the attribute_ok() function. Anything that
# fails either test is removed, and the remainder if any passed to output.

sub _filter_start {
    my ($filter, $tagname, $attr) = @_;
    if ($filter->_tag_ok(lc($tagname))) {
    	for (keys %$attr) {
    		delete $$attr{$_} unless ($filter->_attribute_ok(lc($tagname), lc($_), lc($$attr{$_})));
		}
		my $filtered_tag = "<$tagname" . join('',map(qq| $_="$$attr{$_}"|, keys %$attr)) . ">";
	    $filter->_add_to_output($filtered_tag);
	}
}

# _filter_end(): the designated handler for end tags: tests them against the _tag_ok() function
# and passes them to output if they're acceptable.

sub _filter_end {
    my ($filter, $tagname) = @_;
    $filter->_add_to_output("</$tagname>") if ($filter->_tag_ok(lc($tagname)));
}

=head1 METHODS

=over 4

=item TagFilter->new();

If called without parameters, loads the default set. Otherwise loads the rules you supply. For the rule format, see above.

=item $filter->parse($text);

The parse method is inherited from HTML::Parser, but most of its normal behaviours are subclassed here and the output they normally print is kept for later. The other configuration options that HTML::Parser normally offers are not passed on, at the moment, nor can you override the handler definitions in this module.

=item $filter->output()

calls $filter->eof and returns the accumulated output of the parsing process. This will conclude the processing of your text, but you can of course pass a new piece of text to the same parser object and begin again.

=cut

sub output {
	my $filter = shift;
	$filter->eof;
	return $filter->{output};
}

sub _add_to_output {
	my $filter = shift;
	$filter->{output} .= $_[0];
}

sub _tag_ok {
    my ($filter, $tagname) = @_;
    return 0 unless $filter->{_allows} || $filter->{_denies};
	return 0 if $filter->_check('_denies', 'attributes', $tagname, 'all');
	return 1 if $filter->_check('_allows', 'tags', $tagname);
	return 0;
}

sub _attribute_ok {
    my ($filter, $tagname, $attribute, $value) = @_;    

	return 0 if $filter->_check('_denies','values', $tagname, $attribute, 'any',);
	return 0 if $filter->_check('_denies','values', $tagname, $attribute, $value,);
	return 0 if $filter->_check('_denies','attributes', $tagname, 'any',);

	return 1 if $filter->_check('_allows','values', 'any', $attribute, 'any',);
	return 1 if $filter->_check('_allows','values', 'any', $attribute, $value,);

	return 1 if $filter->_check('_allows','attributes', $tagname, 'any',);
	return 1 if $filter->_check('_allows','values', $tagname, $attribute, 'any',);
	return 1 if $filter->_check('_allows','values', $tagname, $attribute, $value,);
	return 0;
}


# -check(): a private function to test a for value buried deep in a HoHoHo 
# without autovivifying everything above it and cluttering the place up.

sub _check {
	my $filter = shift;
	my $field = shift;
	my @keys = @_;
	warn '_check: no keys' and return unless @keys;
	my $deepref = $filter->{$field};
	for (@keys) {
		warn "_check: $deepref not a hashref" and return unless ref $deepref eq 'HASH';
		return 0 unless $deepref->{$_};
		$deepref = $deepref->{$_};
	}
	return 1;
}

=item $filter->allow_tags($hashref)

Takes a hashref of permissions and requests their translation into the lookup structure we're using to apply rules. The supplied rules are added to what we already have, replacing at the tag level anything that is already here. In other words, you can add a tag to the existing set, but to add an attribute to an existing tag you have to specify the whole set of attribute permissions.  If no rules are sent, this clears the permission rule set.

=item $filter->deny_tags($hashref)

likewise but sets up (or clears) denial rules.

=cut

sub allow_tags {
    my ($filter, $tagset) = @_;
    if ($tagset) {
    	$filter->_configurise('_allows',$tagset);
    } else {
		$filter->{_allows} = {};
    }
}

sub deny_tags {
    my ($filter, $tagset) = @_;
    if ($tagset) {
    	$filter->_configurise('_denies',$tagset);
    } else {
		$filter->{_denies} = {};
    }
}

# _configuruse(): a private function that translates input rules into
# the absurdly complicated HoHoHo's we're using for lookup.

sub _configurise {
    my ($filter, $field, $tagset) = @_;
	foreach my $tag (keys %$tagset) {
		$filter->{$field}->{tags}->{$tag} = 1;
		foreach my $att (keys %{ $tagset->{$tag} }) {
			$filter->{$field}->{attributes}->{$tag}->{$att} = 1;
			$filter->{$field}->{values}->{$tag}->{$att}->{any} = 1 unless 
				defined( $tagset->{$tag}->{$att} ) && @{ $tagset->{$tag}->{$att} };
			foreach my $val (@{ $tagset->{$tag}->{$att} }) {
				$filter->{$field}->{values}->{$tag}->{$att}->{$val} = 1;
			}
		}
	}
}

=item $filter->allows()

Returns the full set of permissions. Can't be set this way: just a utility function in case you want to either display the rule set, or send it back to allow_tags in a modified form.

=item $filter->denies()

Likewise but for denial rules.

=back

=cut

sub allows {
    my $filter = shift;
	return $filter->{_allows};
}

sub denies {
    my $filter = shift;
	return $filter->{_denies};
}

# handler() exists here only to admonish people who try to use this module as they would
# HTML::Parser. Handler definitions in new() therefore have to use SUPER::handler().

sub handler {
	Carp::croak("You can't set handlers for TagFilter.");
}

1;

=head1 TO DO

Simpler rule-definition interface
Complex rules: 
	* tag combinations, 
	* fuzzy matches (qr// ?) 
	* configurable action in response to rule match, eg: delete attribute vs delete whole tag, vs replace value with something more benign.

=head1 REQUIRES

HTML::Parser

=head1 SEE ALSO

L<HTML::Parser>

=head1 AUTHOR

William Ross, will@spanner.org

=head1 COPYRIGHT

Copyright 2001 William Ross

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

=cut
