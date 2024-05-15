package Authorization::AccessControl::Privilege;
use v5.26;
use warnings;

use Data::Compare;
use Readonly;
use Scalar::Util qw(looks_like_number);

use experimental qw(signatures);

use overload
  '""' => 'to_string';

sub new($class, %params) {
  my $role         = delete($params{role});
  my $resource     = delete($params{resource});
  my $action       = delete($params{action});
  my $restrictions = delete($params{restrictions});
  $restrictions = {} unless(defined($restrictions));

  die("Unsupported params: ", join(', ', keys(%params))) if(keys(%params));
  die("Role must be a non-empty string") if   (defined($role) && (ref($role) || $role eq ''));
  die("Resource is required")           unless($resource && !ref($resource));
  die("Action is required")             unless($action && !ref($action ));
  die("Restrictions must be a HashRef") unless(defined($restrictions) && ref($restrictions) eq 'HASH');

  Readonly::Scalar my $data => {
    _role         => $role,
    _resource     => $resource,
    _action       => $action,
    _restrictions => $restrictions
  };

  bless($data, $class);
}

sub to_string($self, @params) {
  my $role = $self->{_role} ? '['.$self->{_role}.'] ' : '';
  my $restrictions = '';
  foreach (keys($self->{_restrictions}->%*)) {
    my $v;
    if($self->{_restrictions}->{$_}) { $v = $self->{_restrictions}->{$_} }
    elsif(looks_like_number($self->{_restrictions}->{$_})) { $v = 0 }
    else { $v = 'false'}
    $restrictions .= "$_=$v,";
  }
  chop($restrictions);
  $role.$self->{_resource}.' => '.$self->{_action}.'('.$restrictions.')';
}

sub role($self) {
  $self->{_role}
}

sub resource($self) {
  $self->{_resource}
}

sub action($self) {
  $self->{_action}
}

sub restrictions($self) {
  $self->{_restrictions}
}

sub satisfies_role($self, @roles) {
  return 1 unless($self->{_role});
  return (grep { $_ eq $self->{_role} } @roles) > 0;
}

sub satisfies_resource($self, $resource) {
  return 0 unless(defined($resource));
  return $self->{_resource} eq $resource
}

sub satisfies_action($self, $action) {
  return 0 unless(defined($action));
  return $self->{_action} eq $action;
}

sub satisfies_restrictions($self, $attributes) {
  my %attrs = $attributes->%*;
  delete($attrs{$_}) foreach (grep { !exists($self->{_restrictions}->{$_}) } keys(%attrs));
  my $v = Compare($self->{_restrictions}, \%attrs);
  return $v;
}

sub is_equal($self, $priv) {
  return 0 unless(($self->role//'') eq ($priv->role//'') );
  return 0 unless($self->resource   eq $priv->resource);
  return 0 unless($self->action     eq $priv->action);
  return 0 unless(Compare($self->restrictions, $priv->restrictions));
  return 1;
}

sub accepts($self, %params) {
  my ($roles, $resource, $action, $attributes) = @params{qw(roles resource action attributes)};

  return 0 unless($self->satisfies_resource($resource));
  return 0 unless($self->satisfies_action($action));
  return 0 unless($self->satisfies_role(($roles//[])->@*));
  return 0 unless($self->satisfies_restrictions($attributes//{}));
  return 1;
}

1;
