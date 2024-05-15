package Authorization::AccessControl::ACL;
use v5.26;
use warnings;

# ABSTRACT: 

use Authorization::AccessControl::Grant;
use Authorization::AccessControl::Request;
use List::Util qw(any);
use Readonly;

use experimental qw(signatures);

sub new($class, %params) {
  my $base = delete($params{base});
  my $role = delete($params{role});

  die("Unsupported params: ", join(', ', keys(%params))) if(keys(%params));

  Readonly::Hash1 my %hooks => (
    on_permit => [],
    on_deny   => []
  );

  Readonly::Hash1 my %data => (
    _base   => $base,
    _role   => $role,
    _grants => ($base ? undef : []), # prevent privs from being saved in non-base instances
    _hooks  => ($base ? undef : \%hooks),
  );
  bless(\%data, $class);
}

sub hook($self, $type, $sub) {
  push($self->_base_instance->{_hooks}->{$type}->@*, $sub);
}

sub clone($self) {
  my $clone = __PACKAGE__->new();
  push($clone->{_grants}->@*, $self->{_grants}->@*);
  return $clone;
}

sub _base_instance($self) {
  $self->{_base} // $self
}

sub role($self, $role = undef) {
  return __PACKAGE__->new(base => $self->_base_instance, role => $role);
}

sub grant($self, $resource, $action, $restrictions = undef) {
  my $p = Authorization::AccessControl::Grant->new(
    role         => $self->{_role},
    resource     => $resource,
    action       => $action,
    restrictions => $restrictions,
  );
  push($self->_base_instance->{_grants}->@*, $p);
  return $self
}

sub __contains($arr, $v) {
  return 0 unless(defined($v));
  any { $_ eq $v } $arr->@*
}

sub get_grants($self, %filters) {
  my @grants = $self->_base_instance->{_grants}->@*;
  @grants = grep { $_->resource eq $filters{resource} } @grants if(exists($filters{resource}));
  @grants = grep { $_->action   eq $filters{action}   } @grants if(exists($filters{action}));
  @grants = grep { __contains($filters{roles}, $_->role) || !defined($_->role) } @grants if(exists($filters{roles}));
  return @grants;
}

sub request($self) {
  warn("Warning: Calling `roles` on the result of `role` or `grant` calls may not yield expected results\n") if($self->{_base});
  return Authorization::AccessControl::Request->new(acl => $self->_base_instance);
}

sub _event($self, $type, $ctx) {
  $_->($ctx) foreach ($self->_base_instance->{_hooks}->{$type}->@*);
}

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
