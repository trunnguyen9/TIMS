import { Component, OnInit } from '@angular/core';
import {DataService} from '../../Services/data.service';

@Component({
  selector: 'app-navbar',
  templateUrl: './navbar.component.html',
  styleUrls: ['./navbar.component.css']
})
export class NavbarComponent implements OnInit {
  isUserLogin: boolean;

  constructor( private dataService: DataService ) {
  }

  ngOnInit() {
    this.dataService.currentLoginStatus.subscribe(isUserLogin => this.isUserLogin = isUserLogin);
  }

}
