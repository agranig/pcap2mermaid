#
# NetPacket::LinuxSLL - Decode and encode Linux SLL (Linux cooked capture
# pseudo-protocol) packets.
#
# $Id: LinuxSLL.pm,v 0.01 2003/00/00 00:00:00 tpot Exp $
#

package NetPacket::LinuxSLL;

#
# Copyright (c) 2003 Greg Zemskov <greg.zemskov@gmail.com>
# Copyright (c) 2008 Dmitry Kokorev <duke@samaramail.ru>
# Copyright (c) 2011 Sergey Afonin <asy@altlinux.ru>
#
# This package is free software and is provided "as is" without express.
# or implied warranty.  It may be used, redistributed and/or modified.
# under the terms of the Artistic License 2.0 (see
# http://opensource.org/licenses/artistic-license-2.0.php)
#

use strict;
use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

BEGIN {
 @ISA = qw(Exporter NetPacket);

 @EXPORT = qw( );

 @EXPORT_OK = qw(
   LINUX_SLL_HOST LINUX_SLL_BROADCAST LINUX_SLL_MULTICAST
   LINUX_SLL_OTHERHOST LINUX_SLL_OUTGOING
 );

 %EXPORT_TAGS = (
   ALL         => [@EXPORT, @EXPORT_OK],
   types       => [qw(
     LINUX_SLL_HOST LINUX_SLL_BROADCAST LINUX_SLL_MULTICAST
     LINUX_SLL_OTHERHOST LINUX_SLL_OUTGOING
   )],
 );
}

use constant LINUX_SLL_HOST        => 0x0000;
use constant LINUX_SLL_BROADCAST   => 0x0001;
use constant LINUX_SLL_MULTICAST   => 0x0002;
use constant LINUX_SLL_OTHERHOST   => 0x0003;
use constant LINUX_SLL_OUTGOING    => 0x0004;

#
# Decode the packet
#

sub decode {
	my $class = shift;
	my ($pkt, $parent, @rest) = @_;
	my $self = {};

	# Class fields

	$self->{_parent} = $parent;
	$self->{_frame} = $pkt;

	# Decode packet

	($self->{type}, $self->{hatype}, $self->{halen}, $self->{addr}, $self->{proto}, $self->{data})
		= unpack('nnna8na*', $pkt);

	bless ($self, $class);
	return $self;
}

sub encode {
	die("Not implemented");
}

1;
