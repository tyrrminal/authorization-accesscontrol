package Authorization::AccessControl;
use v5.26;
use warnings;

# ABSTRACT: Hybrid RBAC/ABAC access control

use Authorization::AccessControl::ACL;

use experimental qw(signatures);

use Exporter 'import';

our @EXPORT_OK = qw(acl);

sub acl() {
  state $acl = Authorization::AccessControl::ACL->new();
  $acl;
}

=head1 NAME

Authorization::AccessControl - hybrid RBAC/ABAC access control

=head1 SYNOPSIS

  use Authorization::AccessControl qw(acl);

  acl
    ->role('admin')
      ->grant(User => 'create')
      ->grant(User => 'delete')
      ->grant(User => 'update')
    ->role
      ->grant(User => 'search')
      ->grant(User => 'Update', { self => true })
      ->grant(Book => 'search')
      ->grant(Book => 'update', { owned => true })
      ->grant(Book => 'delete', { owned => true });

  acl->role("super")->grant(Book => "delete"); 

  acl->request->with_resource('User')->with_action->('create');          # no

  acl->request->with_roles('admin')->with_resource('User')
    ->with_action->('create')->permitted;                                # yes

  acl->request->with_action('search')->with_resource('User')->permitted; # yes

  acl->request->with_roles('admin')->with_resource('User')
    ->with_action('create')->permitted;                                  # yes

  acl->request->with_resource('Book')->with_action('delete')
    ->permitted;                                                         # no

  acl->request->with_resource('Book')->with_action('delete')
    ->with_attributes({ owned => true })
    ->permitted;                                                         # yes
  
  my $user = {id => 4};
  my $get_attrs = sub($obj) { { owned => $obj->{owner_id} == $user->{id} } };
  acl->request->with_resource('Book')->with_action('delete')
    ->with_get_attrs($get_attrs)
    ->yield(sub () { { owner_id => 4, name => "War & Peace" } })
    ->granted(sub($entity) { say $entity })                      # "War & Peace"
    ->is_granted;                                                        # yes

=head1 DESCRIPTION

This is a lightweight library for implementing fine-grained access control in
applications via an intuitive and expressive interface. It features a hybrid
approach, including aspects of both Role-based access control (RBAC) and 
Attribute-based access control (ABAC).

At a high level, the workflow is to populate an access control list with 
privilege grants, then initiate a request against that list with the specific
environment parameters, finally checking if the request is permitted by the list

=head1 FUNCTIONS

=head2 acl

Returns a global persistent instance of L<Authorization::AccessControl::ACL>. 
There's nothing special about this instance other than being globally accessible
-- if your usage requires it, you can manually make as many ACL instances as you
wish and maintain them as you like. This function exists purely as a convenience

Not exported by default.

=head1 AUTHOR

Mark Tyrrell C<< <mark@tyrrminal.dev> >>

=head1 LICENSE

Copyright (c) 2024 Mark Tyrrell

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

=cut

1;

__END__

