##########################################################################
#
#    Neet: Network discovery, enumeration and security assessment tool
#    Copyright (C) 2008-2014 Jonathan Roach
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#    Contact: jonnyhightower [at] funkygeek.com
#
##########################################################################

# Credential manager - using SQLite

# TODO
# > Uniqueness checking when adding entries

package Neet::CredentialManager;

sub new {
	# Used to create a new instance of a credential store
	# Can be used to create a new store, or to open an
	# existing one.
	my $pkg=shift();
	my $path=shift();
	my %credstore;
	my $object=\%credstore;
	bless $object, $pkg;

	#$credstore{'delimit'}="\t";
	$credstore{'create'}=0;
	$credstore{'path'}=$ENV{'HOME'} . "/.credentialManager";
	if (defined($path)){
		$object->credentialStore($path);
	}

	use DBI;
	use DBD::SQLite;

	if (! -f $credstore{'path'}){
		$object->credentialStore($credstore{'path'});
	}
	return $object;
}

sub connectDb {
	my $self=shift();
	my $dbh = DBI->connect("dbi:SQLite:dbname=$$self{'path'}","","");
	if (!defined($dbh)){
		return undef;
	}
	$$self{'dbh'}=$dbh;
	return $dbh;
}

sub credentialStore {
	# Allow the user to select a different credential store
	my $self=shift();
	my $new=shift();
	if (defined($new) && (! -d "$new") && (! -l "$new") && (! -p "$new") && (! -S "$new") && (! -b "$new") && (! -c "$new") && (! -t "$new")){
		if (-z "$new"){
			$$self{'path'}=$new;
			$$self{'create'}=1;
			$self->createStore;
		} elsif (! -f "$new"){
			$$self{'path'}=$new;
			$$self{'create'}=1;
			$self->createStore;
		}	else {
			my $type=`file "$new"`;
			if ($type =~ /SQLite \S+ database/){
				$$self{'path'}=$new;
			}
		}
	} else {
		if (-z $$self{'path'}){
			$$self{'create'}=1;
			$self->createStore;
		} elsif (! -f $$self{'path'}){
			$$self{'create'}=1;
			$self->createStore;
		}
	}
	return $$self{'path'};
}

sub createStore {
	my $self=shift();
	if ($$self{'create'} == 1){
		my $dbh = $self->connectDb();

		if (!defined($dbh)){
			return undef;
		}

		my @queries;
		push @queries, "CREATE TABLE credentials (
			id INT,
			privilege CHAR(8),
			tag CHAR(8),
			type CHAR(8),
			rid CHAR(8),
			user CHAR(30),
			pass CHAR(256),
			domain CHAR(30),
			system CHAR(60),
			comment CHAR(140)
		)";
		push @queries, "CREATE TABLE tracking (
			point INT
		)";
		push @queries, ("INSERT INTO tracking VALUES (0)");

		for my $query (@queries){
			$dbh->do($query);
		}
		$dbh->disconnect;
	}
	return 0;
}

sub errMsg {
	my $self=shift();
	my $msg=shift();
	if (defined($msg)){
		$$self{'errMsg'}=$msg;
	}
	return $$self{'errMsg'};
}

sub addCredential {
	my $self=shift();
	my %data=@_;
	my $haveEnough=0;

	$haveEnough=1 if (defined($data{'pass'}) || defined($data{'user'}));
	if (!$data{'type'}){
		$data{'type'}="smb";
		$data{'type'}="gen" if (!$data{'user'});
	}

	for my $element ("privilege","tag","rid","user","pass","domain","system","comment"){
		$data{$element}="" if (!defined($data{$element}));
	}

	# Always store the type in lower case, and system in upper case.
	# This will avoid problems with the filtering when listing lots
	# of credentials.
	$data{'type'}=lc($data{'type'});	
	$data{'system'}=uc($data{'system'});	

	if ($haveEnough){
		my $dbh = $self->connectDb();
		if (!defined($dbh)){
			return 0;
		}

		# Make sure we have the DB
		if (-z $$self{'path'}){
			$$self{'create'}=1;
			$self->createStore;
		}

		my $sth = $dbh->prepare('SELECT point FROM tracking');
		$sth->execute();
		my $id = $sth->fetchrow;

		# Take care of cases where the domain has been supplied in DOMAIN\User form:
		if (($data{'user'} =~ /\S+\\\w/) && ($data{'domain'} eq "")){
			my ($domain,$user)=split ("\\\\", $data{'user'}, 2);
			$data{'user'}=$user;
			$data{'domain'}=$domain;
		}

		# Take care of cases where the domain has been supplied in user@domain form:
		if (($data{'user'} =~ /\S+\@\S+/) && ($data{'domain'} eq "")){
			my ($user,$domain)=split ("@", $data{'user'}, 2);
			$data{'user'}=$user;
			$data{'domain'}=$domain;
		}
		$sth = $dbh->prepare('INSERT INTO credentials values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
		$sth->execute($id, $data{'privilege'}, $data{'tag'}, $data{'type'}, $data{'rid'}, $data{'user'}, $data{'pass'}, $data{'domain'}, $data{'system'}, $data{'comment'});
		$sth->finish();
		$dbh->disconnect;
		return 0 if (!defined($sth));

		$dbh = $self->connectDb();
		if (!defined($dbh)){
			return 0;
		}
		$id++;
		$sth = $dbh->prepare("UPDATE tracking SET POINT=$id");
		$sth->execute();
		$sth->finish();
		$dbh->disconnect;

		return 1;
	}
	return 0;
}

sub deleteCredential {
	my $self=shift();
	my $id=shift();
	if (-z $$self{'path'}){
		$self->errMsg("The database is empty.");
		return 0;
	}
	my $dbh = $self->connectDb();
	if (!defined($dbh)){
		return 0;
	}
	my $sth = $dbh->prepare('DELETE FROM credentials WHERE ID=?');
	$sth->execute($id);
	$sth->finish();
	return 0 if (!defined($sth));
	$dbh->disconnect;
	return 1;
}

sub selectCredentials {
	my $self=shift();
	my @output;
	my %filter=@_;
	my $filters=0;
	my $id;
	if (-z $$self{'path'}){
		$self->errMsg("The database is empty.");
		return "";
	}
	my $dbh = $self->connectDb();
	if (!defined($dbh)){
		return "";
	}

	my $fieldSelector;
	my $statement	= 'SELECT * FROM credentials';
	my @params;

	my @arrayOfHashes;

	for my $f (keys(%filter)){
		if ($filter{$f}){
			for my $lc ("tag","privilege","type"){
				if ("$f" eq "$lc") {
					$filter{$f}=lc($filter{$f});
				}
			}
			if ("$f" eq "system"){
				$filter{$f}=uc($filter{$f});
			}
			if ("$f" eq "output"){
				$fieldSelector=$filter{$f};
				next;
			}
			$filters++;
			if ($filters == 1){
				$statement .= " WHERE $f LIKE ?";
				push @params, $filter{$f};
			} else {
				$statement .= " AND $f LIKE ?";
				push @params, $filter{$f};
			}
		}
	}

	my @fields;
	if ($fieldSelector){
		for my $select (split ("", $fieldSelector)){
			push @fields, "privilege" if ($select =~ /P/);
			push @fields, "tag" if ($select =~ /g/);
			push @fields, "id" if ($select =~ /i/);
			push @fields, "user" if ($select =~ /u/);
			push @fields, "pass" if ($select =~ /p/);
			push @fields, "type" if ($select =~ /t/);
			push @fields, "system" if ($select =~ /s/);
			push @fields, "domain" if ($select =~ /d/);
			push @fields, "comment" if ($select =~ /c/);
			push @fields, "rid" if ($select =~ /r/);
		}
		my $select = join ",", @fields;
		$statement =~ s/\*/$select/;

	} else {
		@fields=("id","privilege","tag","type","rid","user","pass","domain","system","comment");
	}

	my $sth = $dbh->prepare($statement);
	$sth->execute(@params);

	while (my @row = $sth->fetchrow_array){
		my %dataStore;	
		for my $field (@fields){
			$dataStore{$field}=shift(@row);
		}
		push @arrayOfHashes, \%dataStore;
	}

	$sth->finish();
	$dbh->disconnect();
	return "" if (!defined($sth));
	return @arrayOfHashes;
}

sub modifyCredential {
	my $self=shift();
	my %data=@_;

	# The credential ID to update is supplied by the user
	if (!exists($data{'id'}) || !defined($data{'id'})){
		return 0;
	}
	my $id=$data{'id'};

	# Always store the type in lower case, and system in upper case.
	# This will avoid problems with the filtering when listing lots
	# of credentials.
	$data{'type'}=lc($data{'type'}) if (defined($data{'type'}));	
	$data{'system'}=uc($data{'system'}) if (defined($data{'system'}));	

	my $dbh = $self->connectDb();
	if (!defined($dbh)){
		return 0;
	}

	# Make sure we have the DB
	if (-z $$self{'path'}){
		return 0;
	}

	# Take care of cases where the domain has been supplied in DOMAIN\User form:
	if (defined($data{'user'}) && ($data{'user'} =~ /\S+\\\w/) && !defined($data{'domain'})){
		my ($domain,$user)=split ("\\\\", $data{'user'}, 2);
		$data{'user'}=$user;
		$data{'domain'}=$domain;
	}

	# Take care of cases where the domain has been supplied in user@domain form:
	if (defined($data{'user'}) && ($data{'user'} =~ /\S+\@\S+/) && !defined($data{'domain'})){
		my ($user,$domain)=split ("@", $data{'user'}, 2);
		$data{'user'}=$user;
		$data{'domain'}=$domain;
	}

	# Get the existing data for the credential
	my $sth = $dbh->prepare('SELECT * from credentials where id = ?');
	$sth->execute($id);

	my @fields=("id","privilege","tag","type","rid","user","pass","domain","system","comment");
	my %updated;	

	my @row = $sth->fetchrow;
	return 0 if ($#row < 0);

	for my $field (@fields){
		$updated{$field}=shift(@row);
		# Override the existing data with the user-supplied data
		$updated{$field}=$data{$field} if (defined($data{$field}));
	}
	$sth->finish();

	# Now update the database with the modified data
	$sth = $dbh->prepare('UPDATE credentials SET privilege=?, tag=?, type=?, rid=?, user=?, pass=?, domain=?, system=?, comment=? WHERE id=?');
	$sth->execute($updated{'privilege'}, $updated{'tag'}, $updated{'type'}, $updated{'rid'}, $updated{'user'}, $updated{'pass'}, $updated{'domain'}, $updated{'system'}, $updated{'comment'},$id);
	$sth->finish();
	$dbh->disconnect;

	return 0 if (!defined($sth));
	return 1;
}



1;

