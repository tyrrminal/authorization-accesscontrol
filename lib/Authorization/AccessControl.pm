package Authorization::AccessControl;
use v5.26;
use warnings;

#ABSTRACT: Hybrid RBAC/ABAC access control

use Exporter 'import';

use Authorization::AccessControl::Privilege;
use Authorization::AccessControl::Predicate;
use List::Util qw(any);
use Readonly;

use experimental qw(signatures);

our @EXPORT_OK = qw(ac);

sub ac() {
  state $ac = __PACKAGE__->new();
  $ac;
}

sub new($class, %params) {
  Readonly::Hash1 my %data => (
    _base       => $params{base},
    _role       => $params{role},
    _privs      => ($params{base} ? undef : []), # prevent privs from being saved in non-base instances
  );
  bless(\%data, $class);
}

sub clone($self) {
  my $clone = __PACKAGE__->new();
  push($clone->{_privs}->@*, $self->{_privs}->@*);
  return $clone;
}

sub _base_instance($self) {
  $self->{_base} // $self
}

sub role($self, $role = undef) {
  return __PACKAGE__->new(base => $self->_base_instance, role => $role);
}

sub grant($self, $resource, $action, $restrictions = undef) {
  my $p = Authorization::AccessControl::Privilege->new(
    role         => $self->{_role},
    resource     => $resource,
    action       => $action,
    restrictions => $restrictions,
  );
  push($self->_base_instance->{_privs}->@*, $p);
  return $self
}

sub __contains($arr, $v) {
  return !1 unless(defined($v));
  any { $_ eq $v } $arr->@*
}

sub get_grants($self, %filters) {
  my @grants = $self->_base_instance->{_privs}->@*;
  @grants = grep { $_->resource eq $filters{resource} } @grants if(exists($filters{resource}));
  @grants = grep { $_->action   eq $filters{action}   } @grants if(exists($filters{action}));
  @grants = grep { __contains($filters{roles}, $_->role) || !defined($_->role) } @grants if(exists($filters{roles}));
  return @grants;
}

sub roles($self, @roles) {
  warn("Warning: Calling `roles` on the result of `role` or `grant` calls may not yield expected results\n") if($self->{_base});
  return Authorization::AccessControl::Predicate->new(access_control => $self->_base_instance, roles => [@roles]);
}

1;
