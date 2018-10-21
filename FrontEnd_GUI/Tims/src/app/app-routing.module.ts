import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { LoginComponent } from './Components/login/login.component';
import { HomeComponent } from './Components/home/home.component';
import { ConfigComponent } from './Components/config/config.component';
import { StatisticComponent } from './Components/statistic/statistic.component';
import {AuthGuard} from './Guards/auth.guard';
import {RegisterComponent} from './Components/register/register.component';

const routes: Routes = [
    {
        path: '',
        redirectTo: '/home',
        pathMatch: 'full'
    },
    {
        path: 'home',
        component: HomeComponent
    },
    {
        path: 'login',
        component: LoginComponent
    },
    {
      path: 'register',
      component: RegisterComponent
    },
    {
        path: 'configuration',
        component: ConfigComponent,
        canActivate: [AuthGuard]
    },
    {
        path: 'statistics',
        component: StatisticComponent,
        canActivate: [AuthGuard]
    },
    { path: '**', redirectTo: '/home' }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }


