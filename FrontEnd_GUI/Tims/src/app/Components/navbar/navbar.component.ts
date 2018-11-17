import { Component, OnInit } from '@angular/core';
import {DataService} from '../../Services/data.service';
import {ActivatedRoute, Router} from '@angular/router';
import {AuthenticationService} from '../../Services/authentication.service';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements OnInit {
  isUserLogin: boolean;

  constructor( private dataService: DataService,
               private route: ActivatedRoute,
               private router: Router,
               private authService: AuthenticationService) {
  }

  ngOnInit() {
    this.dataService.currentLoginStatus.subscribe(isUserLogin => this.isUserLogin = isUserLogin);
  }

  logout() {
    this.authService.logout();
    this.dataService.changeLoginStatus(false);
    this.router.navigate(['']);
  }

}
