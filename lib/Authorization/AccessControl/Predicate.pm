package Authorization::AccessControl::Predicate;
use v5.26;
use warnings;

use Authorization::AccessControl::YieldResult;
use Readonly;

use constant true  => !0;
use constant false => !1;

use experimental qw(signatures);

sub new($class, %params) {
  my $ac          = delete($params{access_control});
  my $roles       = delete($params{roles});
  my $resource    = delete($params{resource});
  my $action      = delete($params{action});
  my $attributes  = delete($params{attributes}) // {};
  my $dyn_attrs_f = delete($params{dyn_attrs_f}) // undef;

  die("access_control is a required property") unless(defined($ac) && ref($ac) && $ac->isa('Authorization::AccessControl'));

  Readonly::Scalar my $data => {
    _access_control => $ac,
    _roles          => $roles,
    _resource       => $resource,
    _action         => $action,
    _attributes     => $attributes,
    _dyn_attrs_f    => $dyn_attrs_f,
  };
  bless($data, $class);
}

sub __properties($self) {
  (
    access_control => $self->{_access_control},
    roles          => $self->{_roles},
    resource       => $self->{_resource},
    action         => $self->{_action},
    attributes     => $self->{_attributes},
    dyn_attrs_f    => $self->{_dyn_attrs_f},
  )
}

sub perform($self, $action) {
  return __PACKAGE__->new(
    $self->__properties,
    action => $action,
  );
}

sub on_resource($self, $resource) {
  return __PACKAGE__->new(
    $self->__properties,
    resource       => $resource,
  );
}

sub with_attributes($self, $attrs) {
  return __PACKAGE__->new(
    $self->__properties,
    attributes     => {$self->{_attributes}->%*, $attrs->%*},
  );
}

sub with_dynamic_attribute_extraction_function($self, $sub) {
  return __PACKAGE__->new(
    $self->__properties,
    dyn_attrs_f => $sub,
  );
}

sub permitted($self) {
  return false unless(defined($self->{_resource}));
  return false unless(defined($self->{_action}));

  my @grants = 
    grep { $_->accepts(
      roles          => $self->{_roles},
      resource       => $self->{_resource},
      action         => $self->{_action},
      attributes     => $self->{_attributes},
    ) } 
    $self->{_access_control}->get_grants;
  return $grants[0];
}

sub yield($self, $get_obj) {
  unless(defined($self->{_dyn_attrs_f})) {
    return Authorization::AccessControl::YieldResult->new(granted => false) unless($self->permitted);
    my $obj = $get_obj->();
    return Authorization::AccessControl::YieldResult->new(granted => undef) unless(defined($obj));
    return Authorization::AccessControl::YieldResult->new(granted => true, entity => $obj);
  }
  my $obj = $get_obj->();
  return Authorization::AccessControl::YieldResult->new(granted => undef) unless(defined($obj));

  my $attrs = $self->{_dyn_attrs_f}->($obj);
  $self = $self->with_attributes($attrs);
  return Authorization::AccessControl::YieldResult->new(granted => true, entity => $obj) if($self->permitted);
  return Authorization::AccessControl::YieldResult->new(granted => false);
}

1;
