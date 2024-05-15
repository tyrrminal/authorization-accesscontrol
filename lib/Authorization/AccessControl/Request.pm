package Authorization::AccessControl::Request;
use v5.26;
use warnings;

use Authorization::AccessControl::Dispatch;
use Readonly;
use Scalar::Util qw(looks_like_number);

use constant true  => !0;
use constant false => !1;

use experimental qw(signatures);

use overload
  '""' => \&to_string;

sub new($class, %params) {
  my $acl         = delete($params{acl});
  my $roles       = delete($params{roles});
  my $resource    = delete($params{resource});
  my $action      = delete($params{action});
  my $attributes  = delete($params{attributes}) // {};
  my $dyn_attrs_f = delete($params{dyn_attrs_f}) // undef;

  die("Unsupported params: ", join(', ', keys(%params))) if(keys(%params));
  die("acl is a required property") unless(defined($acl) && ref($acl) && $acl->isa('Authorization::AccessControl::ACL'));

  Readonly::Scalar my $data => {
    _acl            => $acl,
    _roles          => $roles,
    _resource       => $resource,
    _action         => $action,
    _attributes     => $attributes,
    _dyn_attrs_f    => $dyn_attrs_f,
  };
  bless($data, $class);
}

sub to_string($self, @params) {
  my $roles = $self->{_roles}->@* ? '['.join(',', $self->{_roles}->@*).']' : '';
  my $attributes = '';
  my $resource = $self->{_resource} // '{NO_RESOURCE}';
  my $action = $self->{_action} // '{NO_ACTION}';
  foreach (keys($self->{_attributes}->%*)) {
    my $v;
    if($self->{_attributes}->{$_}) { $v = $self->{_attributes}->{$_} }
    elsif(looks_like_number($self->{_attributes}->{$_})) { $v = 0 }
    else { $v = 'false'}
    $attributes .= "$_=$v,";
  }
  chop($attributes);
  $roles.$resource.' => '.$action.'('.$attributes.')';
}

sub __properties($self) {
  (
    acl            => $self->{_acl},
    roles          => $self->{_roles},
    resource       => $self->{_resource},
    action         => $self->{_action},
    attributes     => $self->{_attributes},
    dyn_attrs_f    => $self->{_dyn_attrs_f},
  )
}

sub with_roles($self, @roles) {
  return __PACKAGE__->new(
    $self->__properties,
    roles => [@roles],
  )
}

sub with_action($self, $action) {
  return __PACKAGE__->new(
    $self->__properties,
    action => $action,
  );
}

sub with_resource($self, $resource) {
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
    $self->{_acl}->get_grants;
  if(@grants) {
    $self->{_acl}->_event(on_permit => $grants[0]); 
    return true;
  }
  $self->{_acl}->_event(on_deny => $self);
  return false;
}

sub yield($self, $get_obj) {
  unless(defined($self->{_dyn_attrs_f})) {
    return Authorization::AccessControl::Dispatch->new(granted => false) unless($self->permitted);
    my $obj = $get_obj->();
    return Authorization::AccessControl::Dispatch->new(granted => undef) unless(defined($obj));
    return Authorization::AccessControl::Dispatch->new(granted => true, entity => $obj);
  }
  my $obj = $get_obj->();
  return Authorization::AccessControl::Dispatch->new(granted => undef) unless(defined($obj));

  my $attrs = $self->{_dyn_attrs_f}->($obj);
  $self = $self->with_attributes($attrs);
  return Authorization::AccessControl::Dispatch->new(granted => true, entity => $obj) if($self->permitted);
  return Authorization::AccessControl::Dispatch->new(granted => false);
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
